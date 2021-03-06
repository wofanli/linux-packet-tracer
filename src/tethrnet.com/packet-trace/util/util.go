package util

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/qiniu/log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unsafe"
)

var IsHostBigEndian bool = isHostBigEndian()

//return true if host is big endian
func isHostBigEndian() bool {
	var i uint32 = 1
	var bytes *[4]byte = (*[4]byte)(unsafe.Pointer(&i))
	return bytes[3] == 1
}

func TcpFlag2Str(flag uint16) string {
	str := ""
	if isHostBigEndian() {
		if (flag & 0x8000) != 0 {
			str += ", FIN"
		}
		if (flag & 0x4000) != 0 {
			str += ", SYN"
		}
		if (flag & 0x2000) != 0 {
			str += ", RST"
		}
		if (flag & 0x800) != 0 {
			str += ", ACK"
		}
	} else {
		if (flag & 0x100) != 0 {
			str += ", FIN"
		}
		if (flag & 0x200) != 0 {
			str += ", SYN"
		}
		if (flag & 0x400) != 0 {
			str += ", RST"
		}
		if (flag & 0x1000) != 0 {
			str += ", ACK"
		}
	}
	return str
}

func Ip2Int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func IPMask2Int(mask net.IPMask) uint32 {
	return binary.LittleEndian.Uint32(mask)
}
func Int2Ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

const (
	PROT_ICMP   = 1
	PROT_IGMP   = 2
	PROT_IPinIP = 4
	PROT_TCP    = 6
	PROT_EGP    = 8
	PROT_IGP    = 9
	PROT_UDP    = 0x11
	PROT_GRE    = 0x2f
	PROT_ESP    = 0x32
	PROT_AH     = 0x33
)

func IPv4ProtToStr(prot uint8) string {
	str := "unknown"
	switch prot {
	case PROT_ICMP:
		str = "ICMP"
	case PROT_IGMP:
		str = "IGMP"
	case PROT_IPinIP:
		str = "IPinIP"
	case PROT_TCP:
		str = "TCP"
	case PROT_EGP:
		str = "EGP"
	case PROT_IGP:
		str = "IGP"
	case PROT_UDP:
		str = "UDP"
	case PROT_GRE:
		str = "GRE"
	case PROT_ESP:
		str = "ESP"
	case PROT_AH:
		str = "AH"
	}
	return fmt.Sprintf("%v(0x%x)", str, prot)
}

func PF2Str(pf int) string {
	str := "unknown"
	switch pf {
	case 0:
		str = "NFPROTO_UNSPEC"
	case 1:
		str = "NFPROTO_INET"
	case 2:
		str = "NFPROTO_IPV4"
	case 3:
		str = "NFPROTO_ARP"
	case 5:
		str = "NFPROTO_NETDEV"
	case 7:
		str = "NFPROTO_BRIDGE"
	case 10:
		str = "NFPROTO_IPV6"
	case 12:
		str = "NFPROTO_DECNET"
	}
	str = fmt.Sprintf("%v(%d)", str, pf)
	return str
}

func Hook2Str(hook int) string {
	str := "unknown"
	switch hook {
	case 0:
		str = "NF_INET_PRE_ROUTING"
	case 1:
		str = "NF_INET_LOCAL_IN"
	case 2:
		str = "NF_INET_FORWARD"
	case 3:
		str = "NF_INET_LOCAL_OUT"
	case 4:
		str = "NF_INET_POST_ROUTING"
	case 5:
		str = "NF_INET_NUMHOOKS"
	}
	str = fmt.Sprintf("%v(%d)", str, hook)
	return str
}

func GetInterfaces() map[int]string {
	ret := make(map[int]string)
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("fail to get interface list", err)
	}
	for _, intf := range interfaces {
		ret[intf.Index] = intf.Name
		log.Debugf("found interface mapping:%v,%v\n",
			intf.Index, intf.Name)
	}
	return ret
}

func Pid2Netns(pid int) string {
	cmd := exec.Command("bash", "-c", "ip netns identify "+strconv.Itoa(pid))
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.Trim(string(out), "\n")

}

func GetNameByPid(pid int) string {
	path := "/proc/" + strconv.Itoa(pid) + "/comm"
	fi, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return ""
	}
	defer fi.Close()

	reader := bufio.NewReaderSize(fi, 50)
	if reader != nil {
		name, err := reader.ReadBytes('\n')
		if err == nil {
			return string(name[:len(name)-1])
		}
	}
	return ""
}
