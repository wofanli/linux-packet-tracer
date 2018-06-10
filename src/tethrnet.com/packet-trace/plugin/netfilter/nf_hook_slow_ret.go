package netfilter

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/util"
	"unsafe"
)

const source_nf_hook_slow_ret string = `
// on kprobe, the parameter is can be found in register (varies among archetecture)
// however, we cannot assume the parameter is still stored in the same register after the function ends. 
// Here we cache the meta on kprobe, and kretprobe make use of it. 
// https://stackoverflow.com/questions/8437149/get-syscall-parameters-with-kretprobes-post-handler
int kretprobe__nf_hook_slow(struct pt_regs *ctx){
	log_event_t event = {};
	u32 pid = bpf_get_current_pid_tgid();
	nf_hook_slow_cache_t *cache = nf_hook_slow_cache.lookup(&pid);
	if (!cache) {
		return 0;
	}else {
		event.skb_adr = (u64)(cache->skb);
		u8 exist = get_epoch(&event);
		event.plugin = ___plugintype___;
		sub_event_nf_hook_slow *subevent = (sub_event_nf_hook_slow*)event.desc;

		if (exist==EXIST) {
			subevent->hook = cache->hook;
			subevent->pf = cache->pf;
			int ret = PT_REGS_RC(ctx);
			if (ret == 1) {
				subevent->drop = ___PASS___;
			} else {
				subevent->drop = ___DROP___;
			}
			log_events.perf_submit(ctx,&event, sizeof(event));
		}
		nf_hook_slow_cache.delete(&pid);
	}
	return 0;
}
`

type NF_HOOK_SLOW_RET struct {
}

func NewNfHookSlowRet() *NF_HOOK_SLOW_RET {
	return &NF_HOOK_SLOW_RET{}
}

func (p *NF_HOOK_SLOW_RET) GetType() int {
	return plugin.NF_HOOK_SLOW_RET
}

const (
	DROP = iota
	PASS
)

func (p *NF_HOOK_SLOW_RET) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_nf_hook_slow)(unsafe.Pointer(uintptr(C.CBytes(data))))
	is_pass := "PASS"
	if event.drop == DROP {
		is_pass = "DROP"
	}
	return fmt.Sprintf("%v, %v, check done, %v",
		util.PF2Str(int(event.pf)), util.Hook2Str(int(event.hook)),
		is_pass)
}

func (p *NF_HOOK_SLOW_RET) Init(m *bpf.Module) error {
	return nil
}

func (p *NF_HOOK_SLOW_RET) GetSource() string {
	src := source_nf_hook_slow_ret
	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.NF_HOOK_SLOW_RET), -1)
	src = strings.Replace(src, "___PASS___", strconv.Itoa(PASS), -1)
	src = strings.Replace(src, "___DROP___", strconv.Itoa(DROP), -1)
	return src
}

func (p *NF_HOOK_SLOW_RET) GetProbePoint() (name string, probeType string) {
	return "nf_hook_slow", plugin.KRETPROBE
}

func (p *NF_HOOK_SLOW_RET) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *NF_HOOK_SLOW_RET) NeedProbe() bool {
	return true
}
