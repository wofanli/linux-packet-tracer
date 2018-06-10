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

const source_ip_forward string = `
int kprobe__ip_forward(struct pt_regs *ctx,struct sk_buff *skb){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	event.plugin = ___plugintype___;

	sub_event_ip_rcv *subevent = (sub_event_ip_rcv*)event.desc;

	unsigned char * hdr_ = skb->head + skb->network_header;
	ip_hdr *hdr = (ip_hdr*)hdr_;

	subevent->src = hdr->saddr;
	subevent->dst = hdr->daddr;
	if (classify(subevent->src,subevent->dst) == 0) {
		gen_epoch(&event);
    } else {
        u8 exist = get_epoch(&event);
        if (exist!=EXIST) {
            return 0;
        }
	}
	subevent->tos = hdr->tos;
    subevent->ttl = hdr->ttl;
    subevent->prot = hdr->prot;
    u16 tot_len = hdr->tot_len;
    subevent->tot_len = be16_to_cpu(tot_len);
    log_events.perf_submit(ctx,&event, sizeof(event));
	return 0;
}
`

type IpForward struct {
}

func (p *IpForward) GetType() int {
	return plugin.IP_FORWARD
}

func (p *IpForward) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_rcv)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("%v->%v, tos:0x%x, ttl:%d, protocol:%v, total_len:%d",
		util.Int2Ip(event.src),
		util.Int2Ip(event.dst),
		event.tos, event.ttl,
		util.IPv4ProtToStr(event.prot), event.tot_len)
}

func (p *IpForward) Init(m *bpf.Module) error {
	return nil
}

func (p *IpForward) GetSource() string {
	src := source_ip_forward
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_FORWARD), -1)
}

func (p *IpForward) GetProbePoint() (name string, probeType string) {
	return "ip_forward", plugin.KPROBE
}

func (p *IpForward) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpForward) NeedProbe() bool {
	return true
}
