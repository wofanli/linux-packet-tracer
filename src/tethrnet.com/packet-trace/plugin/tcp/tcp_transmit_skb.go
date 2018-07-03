package tcp

//we have ip_queue_xmit already, which can display enough tcp xmit information

//
//import (
//	"C"
//	"fmt"
//	bpf "github.com/iovisor/gobpf/bcc"
//	"strconv"
//	"strings"
//	"tethrnet.com/packet-trace/plugin"
//	"tethrnet.com/packet-trace/util"
//	"unsafe"
//)
//
//const source_tcp_transmit_skb string = `
//int kprobe__tcp_transmit_skb(struct pt_regs *ctx,struct sock *sk, struct sk_buff *skb){
//	log_event_t event = {};
//	event.skb_adr = (u64)(skb);
//	event.plugin = ___plugintype___;
//	sub_event_tcp_v4 *subevent = (sub_event_tcp_v4*)event.desc;
//	subevent->src = sk->__sk_common.skc_rcv_saddr;
//	subevent->dst = sk->__sk_common.skc_daddr;
//	if (classify(subevent->src, subevent->dst) == 0 || 1) {
//		gen_epoch(&event);
//	} else {
//		u8 exist = get_epoch(&event);
//	    if (exist!=EXIST) {
//			return 0;
//		}
//	}
//	subevent->tcp.dest = sk->__sk_common.skc_dport;
//	log_events.perf_submit(ctx,&event, sizeof(event));
//	return 0;
//}
//`
//
//type TcpV4Xmit struct {
//}
//
//func (p *TcpV4Xmit) GetType() int {
//	return plugin.TCP_V4_XMIT
//}
//
//func (p *TcpV4Xmit) Decode(d [plugin.MAX_MSG_LEN]byte) string {
//	data := d[:]
//	event := (*sub_event_tcp_v4)(unsafe.Pointer(uintptr(C.CBytes(data))))
//	ret := fmt.Sprintf("%v(%d)->%v(%d), seq:%d, ack_seq:%d, window:%d, %s",
//		util.Int2Ip(event.src),
//		event.sport,
//		util.Int2Ip(event.dst),
//		event.dport,
//		event.seq,
//		event.ack_seq,
//		event.window,
//		util.TcpFlag2Str(event.flag))
//	return ret
//}
//
//func (p *TcpV4Xmit) Init(m *bpf.Module) error {
//	return nil
//}
//
//func (p *TcpV4Xmit) GetSource() string {
//	src := source_tcp_transmit_skb
//	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.TCP_V4_XMIT), -1)
//}
//
//func (p *TcpV4Xmit) GetProbePoint() (name string, probeType string) {
//	return "tcp_transmit_skb", plugin.KPROBE
//}
//
//func (p *TcpV4Xmit) GetProbeName() string {
//	name, t := p.GetProbePoint()
//	return t + "__" + name
//}
//
//func (p *TcpV4Xmit) NeedProbe() bool {
//	return true
//}
