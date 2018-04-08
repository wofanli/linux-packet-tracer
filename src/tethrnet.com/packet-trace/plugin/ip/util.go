package ip

import (
	"encoding/binary"
	"fmt"
	"tethrnet.com/packet-trace/plugin/common"
	"tethrnet.com/packet-trace/util"
)

// tcp/udp use big endian
func getPorts(uli [4]byte) (uint16, uint16) {
	dport := binary.BigEndian.Uint16(uli[:2])
	sport := binary.BigEndian.Uint16(uli[2:])
	return sport, dport
}

func decodeTcpUdp(event *sub_event_ip_queue_xmit) string {
	sport, dport := getPorts(event.flowi_uli)
	return fmt.Sprintf("%v(%v:%v)->%v(%v:%v), mark:0x%x, tos:%d, protocol:%v, skb_data_len:%d",
		common.CommonInst.GetIntf(int(event.iif)),
		util.Int2Ip(event.src), sport,
		common.CommonInst.GetIntf(int(event.oif)),
		util.Int2Ip(event.dst), dport,
		event.mark,
		event.tos,
		util.IPv4ProtToStr(event.prot),
		event.skb_data_len)
}

func icmpType2Str(icmpType int) string {
	str := "unknown"
	switch icmpType {
	case 0:
		str = "Echo Reply"
	case 3:
		str = "Unreachable"
	case 5:
		str = "Redirect"
	case 8:
		str = "Echo Request"
	case 11:
		str = "TTL Exceeded"
	}
	str = fmt.Sprintf("%v(%d)", str, icmpType)
	return str
}

func decodeIcmp(event *sub_event_ip_queue_xmit) string {
	icmpType := uint8(event.flowi_uli[0])
	icmpCode := uint8(event.flowi_uli[1])
	return fmt.Sprintf("%v(%v)->%v(%v), mark:0x%x, tos:%d, protocol:%v, icmp type:%d, icmp code: %d",
		common.CommonInst.GetIntf(int(event.iif)),
		util.Int2Ip(event.src),
		common.CommonInst.GetIntf(int(event.oif)),
		util.Int2Ip(event.dst),
		event.mark,
		event.tos,
		util.IPv4ProtToStr(event.prot),
		icmpType2Str(int(icmpType)),
		icmpCode)
}

func decodeGre(event *sub_event_ip_queue_xmit) string {
	greKey := binary.BigEndian.Uint32(event.flowi_uli[:])
	return fmt.Sprintf("%v(%v)->%v(%v), mark:0x%x, tos:%d, protocol:%v, gre key:%d",
		common.CommonInst.GetIntf(int(event.iif)),
		util.Int2Ip(event.src),
		common.CommonInst.GetIntf(int(event.oif)),
		util.Int2Ip(event.dst),
		event.mark,
		event.tos,
		util.IPv4ProtToStr(event.prot), greKey)
}

func decodeEsp(event *sub_event_ip_queue_xmit) string {
	spi := binary.BigEndian.Uint32(event.flowi_uli[:])
	return fmt.Sprintf("%v(%v)->%v(%v), mark:0x%x, tos:%d, protocol:%v, spi:%x",
		common.CommonInst.GetIntf(int(event.iif)),
		util.Int2Ip(event.src),
		common.CommonInst.GetIntf(int(event.oif)),
		util.Int2Ip(event.dst),
		event.mark,
		event.tos,
		util.IPv4ProtToStr(event.prot), spi)
}
