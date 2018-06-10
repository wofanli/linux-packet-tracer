package route

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

const source_fib_validate_source_ret string = `
int kretprobe__fib_validate_source(struct pt_regs *ctx){
	log_event_t event = {};
	u32 pid = bpf_get_current_pid_tgid();
	fib_validate_source_cache_t *cache = fib_validate_source_cache.lookup(&pid);
	if (!cache) {
		return 0;
	}else {
		event.skb_adr = (u64)(cache->skb);
		u8 exist = get_epoch(&event);
		event.plugin = ___plugintype___;
		sub_event_fib_validate_source *subevent = (sub_event_fib_validate_source*)event.desc;

		if (exist==EXIST) {
			subevent->rp_filter_chk = (u32)(PT_REGS_RC(ctx));
			subevent->srcdev = cache->iif;
			subevent->src = cache->src;
			log_events.perf_submit(ctx,&event, sizeof(event));
		}
		nf_hook_slow_cache.delete(&pid);
	}
	return 0;
}
`

type FibValidateSourceRet struct {
}

func (p *FibValidateSourceRet) GetType() int {
	return plugin.FIB_VALIDATE_SOURCE_RET
}

func (p *FibValidateSourceRet) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_fib_validate_source)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("rp_filter check: src(%v), iif(%v),  %v",
		util.Int2Ip(event.src),
		common.CommonInst.GetIntf(int(event.indev)),
		rpFilterChk2Str(int(event.rp_filter_chk)))
}

func (p *FibValidateSourceRet) Init(m *bpf.Module) error {
	return nil
}

func (p *FibValidateSourceRet) GetSource() string {
	src := source_fib_validate_source_ret
	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.FIB_VALIDATE_SOURCE_RET), -1)
	return src
}

func (p *FibValidateSourceRet) GetProbePoint() (name string, probeType string) {
	return "fib_validate_source", plugin.KRETPROBE
}

func (p *FibValidateSourceRet) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *FibValidateSourceRet) NeedProbe() bool {
	return true
}
