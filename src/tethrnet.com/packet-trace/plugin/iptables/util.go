package iptables

import (
	"fmt"
)

func hookRetToStr(ret int) string {
	str := "unknown"
	switch ret {
	case 0:
		str = "NF_DROP"
	case 1:
		str = "NF_ACCEPT"
	case 2:
		str = "NF_STOLEN"
	case 3:
		str = "NF_QUEUE"
	case 4:
		str = "NF_REPEAT"
	case 5:
		str = "NF_STOP"
	}
	return fmt.Sprintf("%v(%d)", str, ret)
}
