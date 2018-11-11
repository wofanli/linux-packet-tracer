package iptables

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

const source_ipt_do_table string = `
typedef struct {
	u64 skb;
	u32 hook;
	u8 pf;
	u8 pad[3];
	char tbl_name[___XT_TABLE_MAXNAMELEN___];
}ipt_do_table_cache_t;

BPF_HASH(ipt_do_table_cache, u32, ipt_do_table_cache_t);

typedef struct {
	u64 indev;
	u64 outdev;
	u32 hook;
	u8 pf;
	u8 ret;
	u8 pad[2];
	u32 mark;
	u32 pad2;
	char tbl_name[___XT_TABLE_MAXNAMELEN___];
}sub_event_ipt_do_table_t;

int kprobe__ipt_do_table(struct pt_regs *ctx, struct sk_buff *skb, 
						 const struct nf_hook_state *state,
						 struct xt_table *table){
	log_event_t event = {};
	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(&event);
	event.plugin = ___plugintype___;
	sub_event_ipt_do_table_t *subevent = (sub_event_ipt_do_table_t*)event.desc;

	if (exist==EXIST) {
		char xt_table_null[] = "null xt_table";
		subevent->indev = state->in->ifindex;
		subevent->outdev = state->out->ifindex;
		subevent->hook = state->hook;
		subevent->pf = state->pf;
		subevent->mark = skb->mark;
		bpf_probe_read(subevent->tbl_name, ___XT_TABLE_MAXNAMELEN___, (void*)(table->name));	
		ipt_do_table_cache_t cache = {};
		cache.skb = (u64)skb;
		cache.hook = state->hook;
		cache.pf = state->pf;
		bpf_probe_read(cache.tbl_name, ___XT_TABLE_MAXNAMELEN___, (void*)(table->name));	
		u32 pid = bpf_get_current_pid_tgid();
		ipt_do_table_cache.update(&pid, &cache);
		log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`
const (
	XT_TABLE_MAXNAMELEN = 32
)

type sub_event_ipt_do_table_t struct {
	indev    uint64
	outdev   uint64
	hook     uint32
	pf       uint8
	ret      uint8
	pad      [2]uint8
	mark     uint32
	pad2     uint32
	tbl_name [XT_TABLE_MAXNAMELEN]byte
}

type IptDoTable struct {
}

func (p *IptDoTable) GetType() int {
	return plugin.IPT_DO_TABLE
}

func (p *IptDoTable) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ipt_do_table_t)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("Will check %v, %v, %v, In_intf:%v, Out_intf:%v, mark:0x%x",
		string(event.tbl_name[:]), //C.GoString(event.tbl_name),
		util.PF2Str(int(event.pf)), util.Hook2Str(int(event.hook)),
		common.CommonInst.GetIntf(int(event.indev)),
		common.CommonInst.GetIntf(int(event.outdev)),
		event.mark)
}

func (p *IptDoTable) Init(m *bpf.Module) error {
	return nil
}

func (p *IptDoTable) GetSource() string {
	src := source_ipt_do_table
	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IPT_DO_TABLE), -1)
	return strings.Replace(src, "___XT_TABLE_MAXNAMELEN___", strconv.Itoa(XT_TABLE_MAXNAMELEN), -1)
}

func (p *IptDoTable) GetProbePoint() (name string, probeType string) {
	return "ipt_do_table", plugin.KPROBE
}

func (p *IptDoTable) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IptDoTable) NeedProbe() bool {
	return true
}
