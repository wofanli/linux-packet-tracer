package iptables

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

const source_ipt_do_table_ret string = `
int kretprobe__ipt_do_table(struct pt_regs *ctx){
	log_event_t event = {};
	u32 pid = bpf_get_current_pid_tgid();
	ipt_do_table_cache_t *cache = ipt_do_table_cache.lookup(&pid);
	if (!cache) {
		return 0;
	}else {
		event.skb_adr = (u64)(cache->skb);
		u8 exist = get_epoch(&event);
		event.plugin = ___plugintype___;
		sub_event_ipt_do_table_t *subevent = (sub_event_ipt_do_table_t*)event.desc;

		if (exist==EXIST) {
			subevent->hook = cache->hook;
			subevent->pf = cache->pf;
			int ret = PT_REGS_RC(ctx);
			subevent->ret = ret;
			bpf_probe_read(subevent->tbl_name, ___XT_TABLE_MAXNAMELEN___, (void*)(cache->tbl_name));
			log_events.perf_submit(ctx,&event, sizeof(event));
		}
		ipt_do_table_cache.delete(&pid);
	}
	return 0;
}
`

type IptDoTableRet struct {
}

func (p *IptDoTableRet) GetType() int {
	return plugin.IPT_DO_TABLE_RET
}

func (p *IptDoTableRet) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ipt_do_table_t)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("%v, %v, %v, check done, %v",
		string(event.tbl_name[:]),
		util.PF2Str(int(event.pf)), util.Hook2Str(int(event.hook)),
		hookRetToStr(int(event.ret)))
}

func (p *IptDoTableRet) Init(m *bpf.Module) error {
	return nil
}

func (p *IptDoTableRet) GetSource() string {
	src := source_ipt_do_table_ret
	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IPT_DO_TABLE_RET), -1)
	src = strings.Replace(src, "___XT_TABLE_MAXNAMELEN___", strconv.Itoa(XT_TABLE_MAXNAMELEN), -1)
	return src
}

func (p *IptDoTableRet) GetProbePoint() (name string, probeType string) {
	return "ipt_do_table", plugin.KRETPROBE
}

func (p *IptDoTableRet) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IptDoTableRet) NeedProbe() bool {
	return true
}
