package ip

/* FIXME:
 * This plugin does not work currently.
 * skb has been freed before.
 * Need some other mechanism.
 */
//
//import (
//	"C"
//	"fmt"
//	bpf "github.com/iovisor/gobpf/bcc"
//	"strconv"
//	"strings"
//	"tethrnet.com/packet-trace/plugin"
//	"unsafe"
//)
//
//const source_ip_rcv_ret string = `
//
//typedef struct {
//	u8 drop;
//} sub_event_ip_rcv_ret;
//
//int kretprobe__ip_rcv(struct pt_regs *ctx,struct sk_buff *skb){
//	log_event_t event = {};
//	u8 status = get_epoch(skb,&event.epoch);
//	if (status==NEW)
//		return 0;
//
//	event.skb_adr = skb;
//	event.plugin = ___plugintype___;
//
//	sub_event_ip_rcv_ret *subevent = event.desc;
//	int ret = PT_REGS_RC(ctx);
//	if (ret == NET_RX_DROP) {
//		subevent->drop = ___DROP___;
//	}
//	return 0;
//}
//`
//
//const (
//	DROP = 1
//)
//
//type sub_event_ip_rcv_ret struct {
//	drop uint8
//}
//
//type IpRecvRet struct {
//}
//
//func (p *IpRecvRet) GetType() int {
//	return plugin.IP_RCV_RET
//}
//
//func (p *IpRecvRet) Decode(d [plugin.MAX_MSG_LEN]byte) string {
//	data := d[:]
//	event := (*sub_event_ip_rcv_ret)(unsafe.Pointer(uintptr(C.CBytes(data))))
//	if event.drop == DROP {
//		return fmt.Sprintln("Drop on IP_RECV")
//	} else {
//		return fmt.Sprintln("Not drop on IP_RECV")
//	}
//}
//
//func (p *IpRecvRet) Init(m *bpf.Module) error {
//	return nil
//}
//
//func (p *IpRecvRet) GetSource() string {
//	src := source_ip_rcv_ret
//	src = strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_RCV), -1)
//	src = strings.Replace(src, "___DROP___", strconv.Itoa(DROP), -1)
//	return src
//}
//
//func (p *IpRecvRet) GetProbePoint() (name string, probeType string) {
//	return "ip_rcv", plugin.KRETPROBE
//}
//
//func (p *IpRecvRet) GetProbeName() string {
//	name, t := p.GetProbePoint()
//	return t + "__" + name
//}
//
//func (p *IpRecvRet) NeedProbe() bool {
//	return true
//}
