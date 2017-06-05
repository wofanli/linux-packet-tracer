package ip

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

const source_ip_send_skb string = `
// icmp echo request will invoke this function to send out packets
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	event.plugin = ___plugintype___;

	sub_event_ip_rcv *subevent = (sub_event_ip_rcv*)event.desc;

	unsigned char * hdr_ = skb->head + skb->network_header;
	ip_hdr *hdr = (ip_hdr*)hdr_;

	subevent->src = hdr->saddr;
	subevent->dst = hdr->daddr;
	if (classify(subevent->src,subevent->dst) == 0) {
		gen_epoch(event.skb_adr,&event.epoch, &event.id);
		subevent->tos = hdr->tos;
		subevent->ttl = hdr->ttl;
		subevent->prot = hdr->prot;
		subevent->tot_len = skb->len;
	  log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type IpSendSkb struct {
}

func (p *IpSendSkb) GetType() int {
	return plugin.IP_SEND_SKB
}

func (p *IpSendSkb) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_rcv)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("%v->%v, tos:0x%x, ttl:%d, protocol:%v, total_len:%d",
		util.Int2Ip(event.src),
		util.Int2Ip(event.dst),
		event.tos, event.ttl,
		util.IPv4ProtToStr(event.prot), event.tot_len)
}

func (p *IpSendSkb) Init(m *bpf.Module) error {
	return nil
}

func (p *IpSendSkb) GetSource() string {
	src := source_ip_send_skb
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_SEND_SKB), -1)
}

func (p *IpSendSkb) GetProbePoint() (name string, probeType string) {
	return "ip_send_skb", plugin.KPROBE
}

func (p *IpSendSkb) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpSendSkb) NeedProbe() bool {
	return true
}
