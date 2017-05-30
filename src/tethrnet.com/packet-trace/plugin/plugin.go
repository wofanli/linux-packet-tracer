package plugin

import (
	"errors"
	bpf "github.com/iovisor/gobpf/bcc"
	"tethrnet.com/packet-trace/log"
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
	IP_QUEUE_XMIT
	IP_FINISH_OUTPUT
	IP_FORWARD
	IP_FORWARD_FINISH
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
)

//func GetPluginTypeStr(t int) string {
//	switch t {
//	case COMMON:
//		return "common"
//	case CLASSIFIER:
//		return "classifier"
//	case IP_RCV:
//		return "ip_rcv"
//	default:
//		return "unknown"
//	}
//}

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
