package tunnel

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

const source_gre string = `
typedef struct {
	u64    if_idx;
	ip_hdr inner;
	ip_hdr outter;
} sub_event_tunnel;

int kprobe__ip_tunnel_xmit(struct pt_regs *ctx,struct sk_buff *skb, struct net_device *dev, const struct iphdr *tnl_params,u8 protocol){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	u8 exist = get_epoch(&event);
	event.plugin = ___plugintype___;
	sub_event_tunnel *subevent = (sub_event_tunnel*)event.desc;
	
	if (exist==EXIST) {
		unsigned char * hdr_ = skb->head + skb->inner_network_header;
		ip_hdr *hdr = (ip_hdr*)hdr_;
		subevent->inner.saddr = hdr->saddr;
		subevent->inner.daddr = hdr->daddr;
		subevent->inner.tos = hdr->tos;
		subevent->inner.ttl = hdr->ttl;
		subevent->inner.prot = hdr->prot;
		u16 tot_len = hdr->tot_len;
		subevent->inner.tot_len = be16_to_cpu(tot_len);

		hdr = (ip_hdr*)tnl_params;
		subevent->outter.saddr = hdr->saddr;
		subevent->outter.daddr = hdr->daddr;
		subevent->outter.tos = hdr->tos;
		subevent->outter.ttl = hdr->ttl;
		subevent->outter.prot = hdr->prot;
		tot_len = hdr->tot_len;
		subevent->outter.tot_len = be16_to_cpu(tot_len);
		subevent->if_idx = dev->ifindex;
	    log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type sub_event_tunnel struct {
	ifIdx         uint64
	inner, outter common.Sub_event_ip_hdr
}

type IpTunnelXmit struct {
}

func (p *IpTunnelXmit) GetType() int {
	return plugin.IP_TUNNEL_XMIT
}

func (p *IpTunnelXmit) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_tunnel)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("ip tunnel egress(%v), outter hdr: %v->%v, tos:0x%x, ttl:%d, protocol:%v, total_len:%d, inner hdr: %v->%v, tos:0x%x, ttl:%d, protocol:%v, total_len:%d",
		common.CommonInst.GetIntf(int(event.ifIdx)),
		util.Int2Ip(event.outter.Src),
		util.Int2Ip(event.outter.Dst),
		event.outter.Tos, event.outter.Ttl,
		util.IPv4ProtToStr(event.outter.Prot), event.outter.Tot_len,
		util.Int2Ip(event.inner.Src),
		util.Int2Ip(event.inner.Dst),
		event.inner.Tos, event.inner.Ttl,
		util.IPv4ProtToStr(event.inner.Prot), event.inner.Tot_len)
}

func (p *IpTunnelXmit) Init(m *bpf.Module) error {
	return nil
}

func (p *IpTunnelXmit) GetSource() string {
	src := source_gre
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_TUNNEL_XMIT), -1)
}

func (p *IpTunnelXmit) GetProbePoint() (name string, probeType string) {
	return "ip_tunnel_xmit", plugin.KPROBE
}

func (p *IpTunnelXmit) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpTunnelXmit) NeedProbe() bool {
	return true
}
