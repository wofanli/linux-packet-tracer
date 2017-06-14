package ip

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_ip_error string = `
int kprobe__ip_error(struct pt_regs *ctx,struct sk_buff *skb){
	log_event_t event = {};
	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(event.skb_adr,&event.epoch, &event.id);
	event.plugin = ___plugintype___;

	if (exist==EXIST) {
		log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type IpError struct {
}

func (p *IpError) GetType() int {
	return plugin.IP_ERROR
}

func (p *IpError) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	str := fmt.Sprintf("pkt processing fails, check previous step")
	return str
}

func (p *IpError) Init(m *bpf.Module) error {
	return nil
}

func (p *IpError) GetSource() string {
	src := source_ip_error
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_ERROR), -1)
}

func (p *IpError) GetProbePoint() (name string, probeType string) {
	return "ip_error", plugin.KPROBE
}

func (p *IpError) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpError) NeedProbe() bool {
	return true
}
