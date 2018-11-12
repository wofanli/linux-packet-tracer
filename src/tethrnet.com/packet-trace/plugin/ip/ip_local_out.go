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

const source_ip_local_out string = `
typedef struct {
	u32 src;
	u32 dst;
	u8 tos;
	u8 ttl;
	u8 prot;
	u8 pad;
	u16 tot_len;
	u8 icmp_type;
	u8 icmp_code;
	u32 mark;
} sub_event_ip_local_out;

int kprobe__ip_local_out(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	event.plugin = ___plugintype___;

	sub_event_ip_local_out *subevent = (sub_event_ip_local_out*)event.desc;

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
	subevent->mark = skb->mark;
	log_events.perf_submit(ctx,&event, sizeof(event));
	
	return 0;
}
`

type sub_event_ip_local_out struct {
	src       uint32
	dst       uint32
	tos       uint8
	ttl       uint8
	prot      uint8
	pad       uint8
	tot_len   uint16
	icmp_type uint8
	icmp_code uint8
	mark      uint32
}

type IpLocalOut struct {
}

func (p *IpLocalOut) GetType() int {
	return plugin.IP_LOCAL_OUT
}

func (p *IpLocalOut) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_local_out)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("%v->%v, tos:0x%x, ttl:%d, protocol:%v, total_len:%d, mark:0x%x",
		util.Int2Ip(event.src),
		util.Int2Ip(event.dst),
		event.tos, event.ttl,
		util.IPv4ProtToStr(event.prot), event.tot_len,
		event.mark)
}

func (p *IpLocalOut) Init(m *bpf.Module) error {
	return nil
}

func (p *IpLocalOut) GetSource() string {
	src := source_ip_local_out
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_LOCAL_OUT), -1)
}

func (p *IpLocalOut) GetProbePoint() (name string, probeType string) {
	return "ip_local_out", plugin.KPROBE
}

func (p *IpLocalOut) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpLocalOut) NeedProbe() bool {
	return true
}
