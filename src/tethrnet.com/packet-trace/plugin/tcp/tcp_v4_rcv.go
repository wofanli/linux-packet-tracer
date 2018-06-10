package tcp

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

const source_tcp_v4_rcv string = `
typedef struct {
	u32 src;
	u32 dst;
	tcp_hdr tcp;
} sub_event_tcp_v4_rcv;

int kprobe__tcp_v4_rcv(struct pt_regs *ctx,struct sk_buff *skb){
	log_event_t event = {};
	event.skb_adr = (u64)(skb);
	event.plugin = ___plugintype___;
	sub_event_tcp_v4_rcv *subevent = (sub_event_tcp_v4_rcv*)event.desc;

	u8 exist = get_epoch(&event);
	if (exist==EXIST) {
		unsigned char * hdr_ = skb->head + skb->network_header;
		ip_hdr *hdr = (ip_hdr*)hdr_;
		subevent->src = hdr->saddr;
		subevent->dst = hdr->daddr;
		hdr_ = skb->head + skb->transport_header;
		tcp_hdr *th = (tcp_hdr*)hdr_;
		subevent->tcp = *th;
		log_events.perf_submit(ctx,&event, sizeof(event));
	}
	
	return 0;
}
`

type sub_event_tcp_v4_rcv struct {
	src     uint32
	dst     uint32
	seq     uint32
	ack_seq uint32
	sport   uint16
	dport   uint16
	window  uint16
	flag    uint16
}

type TcpV4Rcv struct {
}

func (p *TcpV4Rcv) GetType() int {
	return plugin.TCP_V4_RCV
}

func (p *TcpV4Rcv) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_tcp_v4_rcv)(unsafe.Pointer(uintptr(C.CBytes(data))))
	ret := fmt.Sprintf("%v(%d)->%v(%d), seq:%d, ack_seq:%d, window:%d, %s",
		util.Int2Ip(event.src),
		event.sport,
		util.Int2Ip(event.dst),
		event.dport,
		event.seq,
		event.ack_seq,
		event.window,
		util.TcpFlag2Str(event.flag))
	return ret
}

func (p *TcpV4Rcv) Init(m *bpf.Module) error {
	return nil
}

func (p *TcpV4Rcv) GetSource() string {
	src := source_tcp_v4_rcv
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.TCP_V4_RCV), -1)
}

func (p *TcpV4Rcv) GetProbePoint() (name string, probeType string) {
	return "tcp_v4_rcv", plugin.KPROBE
}

func (p *TcpV4Rcv) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *TcpV4Rcv) NeedProbe() bool {
	return true
}
