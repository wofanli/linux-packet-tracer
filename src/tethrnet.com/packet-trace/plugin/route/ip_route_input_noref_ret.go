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

const source_ip_route_input_noref_ret string = `
int kretprobe__ip_route_input_noref(struct pt_regs *ctx){
	log_event_t event = {};
	u32 pid = bpf_get_current_pid_tgid();
	ip_route_input_noref_cache_t *cache = ip_route_input_noref_cache.lookup(&pid);
	if (!cache) {
		return 0;
	}else {
		event.skb_adr = (u64)(cache->skb);
		u8 exist = get_epoch(event.skb_adr,&event.epoch, &event.id);
		event.plugin = ___plugintype___;
		sub_event_ip_route_input_noref *subevent = (sub_event_ip_route_input_noref*)event.desc;

		if (exist==EXIST) {
			subevent->err = (u32)(PT_REGS_RC(ctx));
			subevent->iif = cache->iif;
			subevent->src = cache->src;
			subevent->dst = cache->dst;
			log_events.perf_submit(ctx,&event, sizeof(event));
		}
		ip_route_input_noref_cache.delete(&pid);
	}
	return 0;
}
`

type IpRouteInputNorefRet struct {
}

func (p *IpRouteInputNorefRet) GetType() int {
	return plugin.IP_ROUTE_INPUT_NOREF_RET
}

func (p *IpRouteInputNorefRet) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_route_input_noref)(unsafe.Pointer(uintptr(C.CBytes(data))))
	errStr := "no route. Check route table & ip_forward & rp_filter config"
	if event.err == 0 {
		errStr = "found route"
	}
	return fmt.Sprintf("ip route lookup: dst(%v), src(%v), iif(%v),  %v",
		util.Int2Ip(event.dst),
		util.Int2Ip(event.src),
		common.CommonInst.GetIntf(int(event.iif)),
		errStr)
}

func (p *IpRouteInputNorefRet) Init(m *bpf.Module) error {
	return nil
}

func (p *IpRouteInputNorefRet) GetSource() string {
	src := source_ip_route_input_noref_ret
	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_ROUTE_INPUT_NOREF_RET), -1)
	return src
}

func (p *IpRouteInputNorefRet) GetProbePoint() (name string, probeType string) {
	return "ip_route_input_noref", plugin.KRETPROBE
}

func (p *IpRouteInputNorefRet) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpRouteInputNorefRet) NeedProbe() bool {
	return true
}
