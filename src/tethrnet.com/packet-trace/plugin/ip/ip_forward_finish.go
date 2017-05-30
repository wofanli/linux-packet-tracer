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

const source_ip_forward_finish string = `
int kprobe__ip_forward_finish(struct pt_regs *ctx,struct net *net, struct sock *sk, struct sk_buff *skb){
	log_event_t event = {};
	sub_event_ip_rcv_finish *subevent = (sub_event_ip_rcv_finish*)event.desc;
	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(event.skb_adr,&event.epoch, &event.id);
	event.plugin = ___plugintype___;

	if (exist==EXIST) {
		unsigned char * hdr_ = skb->head + skb->network_header;
		ip_hdr *hdr = (ip_hdr*)hdr_;
		subevent->prot = hdr->prot;
		if (subevent->prot == 1) {
			hdr_ = skb->head + skb->transport_header;
			icmp_hdr_t *icmp_hdr = (icmp_hdr_t*)hdr_ ;
			subevent->icmp_type = icmp_hdr->type;
			subevent->icmp_code = icmp_hdr->code; 
		}	
		log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type IpForwardFinish struct {
}

func (p *IpForwardFinish) GetType() int {
	return plugin.IP_FORWARD_FINISH
}

func (p *IpForwardFinish) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_rcv_finish)(unsafe.Pointer(uintptr(C.CBytes(data))))
	str := fmt.Sprintf("FORWARD check passed, %v", util.IPv4ProtToStr(event.prot))
	if event.prot == util.PROT_ICMP {
		str = fmt.Sprintf("%v, %v(code:%d)", str, icmpType2Str(int(event.icmp_type)), event.icmp_code)
	}
	return str
}

func (p *IpForwardFinish) Init(m *bpf.Module) error {
	return nil
}

func (p *IpForwardFinish) GetSource() string {
	src := source_ip_forward_finish
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_FORWARD_FINISH), -1)
}

func (p *IpForwardFinish) GetProbePoint() (name string, probeType string) {
	return "ip_forward_finish", plugin.KPROBE
}

func (p *IpForwardFinish) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpForwardFinish) NeedProbe() bool {
	return true
}
