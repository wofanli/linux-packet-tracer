package tunnel

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"unsafe"
)

const source_iptunnel_xmit_core string = `

int kprobe__iptunnel_xmit(struct pt_regs *ctx, struct sock *sk, struct rtable *rt, struct sk_buff *skb){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	u8 exist = get_epoch(&event);
	event.plugin = ___plugintype___;
	sub_event_tunnel *subevent = (sub_event_tunnel*)event.desc;
	
	if (exist==EXIST) {
		subevent->mark = skb->mark;
	    log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type IpTunnelXmitCore struct {
}

func (p *IpTunnelXmitCore) GetType() int {
	return plugin.IP_TUNNEL_XMIT_CORE
}

func (p *IpTunnelXmitCore) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_tunnel)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("ip tunnel core egress, mark:0x%x",
		event.mark)
}

func (p *IpTunnelXmitCore) Init(m *bpf.Module) error {
	return nil
}

func (p *IpTunnelXmitCore) GetSource() string {
	src := source_iptunnel_xmit_core
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_TUNNEL_XMIT_CORE), -1)
}

func (p *IpTunnelXmitCore) GetProbePoint() (name string, probeType string) {
	return "iptunnel_xmit", plugin.KPROBE
}

func (p *IpTunnelXmitCore) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpTunnelXmitCore) NeedProbe() bool {
	return true
}
