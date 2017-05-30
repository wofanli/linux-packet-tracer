package netfilter

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/plugin/common"
	"tethrnet.com/packet-trace/util"
	"unsafe"
)

const source_nf_hook_slow string = `

// once kprobe_nf_hook_slow hook is invokded, we cache the pointer here, 
// so that kretprobe_nf_hook_slow can acces the data here. 
typedef struct {
	u64 skb;
	/* FIXME:
	 * initial try is to cache the state pointer,
	 * which fails with "R7 invalid mem access 'inv'".
	 * Don't know the reason yet.
	 * Does BPF allow indirect memory access?
	 */
	u32 hook;
	u8 pf;
	u8 pad[3];
}nf_hook_slow_cache_t;

BPF_HASH(nf_hook_slow_cache, u32, nf_hook_slow_cache_t);

typedef struct {
	u64 indev;
	u64 outdev;
	u32 hook;
	u8 pf;
	u8 drop;
	u8 pad[2];
}sub_event_nf_hook_slow;

int kprobe__nf_hook_slow(struct pt_regs *ctx, struct sk_buff *skb, struct nf_hook_state *state){
	log_event_t event = {};
	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(event.skb_adr,&event.epoch, &event.id);
	event.plugin = ___plugintype___;
	sub_event_nf_hook_slow *subevent = (sub_event_nf_hook_slow*)event.desc;

	if (exist==EXIST) {
		subevent->indev = state->in->ifindex;
		subevent->outdev = state->out->ifindex;
		subevent->hook = state->hook;
		subevent->pf = state->pf;
		nf_hook_slow_cache_t cache = {};
		cache.skb = (u64)skb;
		cache.hook = state->hook;
		cache.pf = state->pf;
		u32 pid = bpf_get_current_pid_tgid();
		nf_hook_slow_cache.update(&pid, &cache);
		log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type sub_event_nf_hook_slow struct {
	indev  uint64
	outdev uint64
	hook   uint32
	pf     uint8
	drop   uint8
}

type NF_HOOK_SLOW struct {
}

func NewNfHookSlow() *NF_HOOK_SLOW {
	return &NF_HOOK_SLOW{}
}

func (p *NF_HOOK_SLOW) GetType() int {
	return plugin.NF_HOOK_SLOW
}

func (p *NF_HOOK_SLOW) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_nf_hook_slow)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("Will check %v, %v, In_intf:%v, Out_intf:%v",
		util.PF2Str(int(event.pf)), util.Hook2Str(int(event.hook)),
		common.CommonInst.GetIntf(int(event.indev)),
		common.CommonInst.GetIntf(int(event.outdev)))
}

func (p *NF_HOOK_SLOW) Init(m *bpf.Module) error {
	return nil
}

func (p *NF_HOOK_SLOW) GetSource() string {
	src := source_nf_hook_slow
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.NF_HOOK_SLOW), -1)
}

func (p *NF_HOOK_SLOW) GetProbePoint() (name string, probeType string) {
	return "nf_hook_slow", plugin.KPROBE
}

func (p *NF_HOOK_SLOW) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *NF_HOOK_SLOW) NeedProbe() bool {
	return true
}
