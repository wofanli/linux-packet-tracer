package plugin

import (
	"errors"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/qiniu/log"
)

const (
	MAX_MSG_LEN = 108
)

type Api interface {
	GetType() int
	GetSource() string
	GetProbePoint() (name string, probeType string)
	GetProbeName() string
	NeedProbe() bool
	Init(*bpf.Module) error
	Decode([MAX_MSG_LEN]byte) string
}

const (
	COMMON = iota
	CLASSIFIER
	IP_RCV
	IP_RCV_RET
	IP_RCV_FINISH
	IP_ERROR
	IP_QUEUE_XMIT
	IP_FINISH_OUTPUT
	IP_FORWARD
	IP_FORWARD_FINISH
	IP_SEND_SKB
	NF_HOOK_SLOW
	NF_HOOK_SLOW_RET
	KFREE_SKB
	SKB_FREE_ALL
	CONSUME_SKB
	KFREE_SKB_PARTIAL
	NAPI_CONSUME_SKB
	IPT_DO_TABLE
	IPT_DO_TABLE_RET
	FIB_VALIDATE_SOURCE
	FIB_VALIDATE_SOURCE_RET
	IP_ROUTE_INPUT_NOREF
	IP_ROUTE_INPUT_NOREF_RET
	IP_TUNNEL_XMIT
	TCP_V4_RCV
)

func PluginId2Str(t uint32) string {
	switch t {
	case COMMON:
		return "common"
	case CLASSIFIER:
		return "classifier"
	case IP_RCV:
		return "ip_rcv"
	case IP_RCV_RET:
		return "ip_rcv return"
	case IP_RCV_FINISH:
		return "callback after Pre Routing"
	case IP_QUEUE_XMIT:
		return "ip_queue_xmit"
	case IP_FINISH_OUTPUT:
		return "callback after Post Routing"
	case IP_FORWARD:
		return "ip_forward"
	case IP_FORWARD_FINISH:
		return "ip_forward return"
	case NF_HOOK_SLOW:
		return "Netfilter"
	case NF_HOOK_SLOW_RET:
		return "Netfilter return"
	case KFREE_SKB:
		return "kfree_skb"
	case SKB_FREE_ALL:
		return "skb_free_all"
	case CONSUME_SKB:
		return "consume_skb"
	case KFREE_SKB_PARTIAL:
		return "kfree_skb_partial"
	case NAPI_CONSUME_SKB:
		return "napi_consume_skb"
	case IPT_DO_TABLE:
		return "Iptables"
	case IPT_DO_TABLE_RET:
		return "Iptables return"
	case FIB_VALIDATE_SOURCE:
		return "rp_filter check"
	case FIB_VALIDATE_SOURCE_RET:
		return "rp_filter check"
	case IP_ROUTE_INPUT_NOREF:
		return "ip fib lookup"
	case IP_ROUTE_INPUT_NOREF_RET:
		return "ip fib lookup finish"
	default:
		return ""
	}
}

type Plugins struct {
	Apis []Api
}

func NewPlugins() *Plugins {
	return &Plugins{
		Apis: []Api{},
	}
}

var (
	INVALID = errors.New("invalid apis")
)

func (p *Plugins) Validate() error {
	if len(p.Apis) <= 2 {
		log.Error("Plugins Validate fails. No enough apis")
		return INVALID
	}
	if p.Apis[0].GetType() != COMMON {
		log.Error("Plugins Validate fails, not start with common", p.Apis[0].GetType())
		return INVALID
	}
	if p.Apis[1].GetType() != CLASSIFIER {
		log.Error("Plugins Validate fails, not correct classifier")
		return INVALID
	}
	return nil
}

func (p *Plugins) GetSource() (string, error) {
	err := p.Validate()
	if err != nil {
		return "", err
	}
	src := ""
	for _, api := range p.Apis {
		src += api.GetSource()
	}
	return src, nil
}

func (p *Plugins) Append(api ...Api) {
	for _, a := range api {
		dup := false
		for _, api := range p.Apis {
			if api.GetType() == a.GetType() {
				log.Println("Existing Plugin has been enabled", a.GetType(), a.GetProbeName())
				dup = true
				continue
			}
		}
		if dup == false {
			log.Debug("append a new plugin", a.GetType(), a.GetProbeName())
			p.Apis = append(p.Apis, a)
		}
	}
}

func (p *Plugins) Get(id int) Api {
	for _, a := range p.Apis {
		if a.GetType() == id {
			return a
		}
	}
	return nil
}
