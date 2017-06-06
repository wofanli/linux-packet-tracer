package ip

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

const source_ip_queue_xmit string = `
typedef struct {
	u64 oif;
	u64 iif;
	u32 src;
	u32 dst;
	u32 mark;
	u16 sport;
	u16 dport;
	u8 tos;
	u8 prot;
	u16 pad;
	u32 flowi_uli;	
} sub_event_ip_queue_xmit;

int kprobe__ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, struct flowi *fl){
	log_event_t event = {};

	event.skb_adr = (u64)(skb);
	event.plugin = ___plugintype___;

	sub_event_ip_queue_xmit *subevent = (sub_event_ip_queue_xmit*)event.desc;
	subevent->src = fl->u.ip4.saddr;
	subevent->dst = fl->u.ip4.daddr;

	if (classify(subevent->src,subevent->dst) == 0) {
		gen_epoch(event.skb_adr,&event.epoch, &event.id);
   	} else { 
		u8 exist = get_epoch(event.skb_adr,&event.epoch, &event.id);
		if (exist!=EXIST) {
			return 0;
		}
	}
	subevent->oif  =  fl->u.ip4.flowi4_oif;
	subevent->iif  =  fl->u.ip4.flowi4_iif;
	subevent->mark = fl->u.ip4.flowi4_mark;
	subevent->tos  =  fl->u.ip4.flowi4_tos;
	subevent->prot = fl->u.ip4.flowi4_proto;
	subevent->flowi_uli = fl->u.ip4.fl4_gre_key;
	log_events.perf_submit(ctx,&event, sizeof(event));
	return 0;
}
`

type sub_event_ip_queue_xmit struct {
	oif, iif       uint64
	src, dst, mark uint32
	sport, dport   uint16
	tos, prot      uint8
	pad            uint16
	flowi_uli      [4]byte
}

type IpQueueXmit struct {
}

func (p *IpQueueXmit) GetType() int {
	return plugin.IP_QUEUE_XMIT
}

func (p *IpQueueXmit) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_queue_xmit)(unsafe.Pointer(uintptr(C.CBytes(data))))
	switch event.prot {
	case util.PROT_TCP:
		return decodeTcpUdp(event)
	case util.PROT_UDP:
		return decodeTcpUdp(event)
	case util.PROT_ICMP:
		return decodeIcmp(event)
	case util.PROT_GRE:
		return decodeGre(event)
	case util.PROT_ESP:
		return decodeEsp(event)
	default:
		return fmt.Sprintf("%v(%v:%v)->%v(%v:%v), mark:0x%x, tos:%d, protocol:%v, flowi_uli:%v",
			common.CommonInst.GetIntf(int(event.iif)),
			util.Int2Ip(event.src), event.sport,
			common.CommonInst.GetIntf(int(event.oif)),
			util.Int2Ip(event.dst), event.dport,
			event.mark,
			event.tos,
			util.IPv4ProtToStr(event.prot),
			event.flowi_uli)
	}
}

func (p *IpQueueXmit) Init(m *bpf.Module) error {
	return nil
}

func (p *IpQueueXmit) GetSource() string {
	src := source_ip_queue_xmit
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_QUEUE_XMIT), -1)
}

func (p *IpQueueXmit) GetProbePoint() (name string, probeType string) {
	return "ip_queue_xmit", plugin.KPROBE
}

func (p *IpQueueXmit) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpQueueXmit) NeedProbe() bool {
	return true
}
