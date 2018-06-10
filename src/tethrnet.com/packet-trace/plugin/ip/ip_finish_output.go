package ip

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_ip_finish_output string = `
int kprobe__ip_finish_output(struct pt_regs *ctx,struct net *net, struct sock *sk, struct sk_buff *skb){
	log_event_t event = {};

	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(&event);
	event.plugin = ___plugintype___;

	if (exist==EXIST) {
	  log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type IpFinishOutput struct {
}

func (p *IpFinishOutput) GetType() int {
	return plugin.IP_FINISH_OUTPUT
}

func (p *IpFinishOutput) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return fmt.Sprintf("POST_ROUTING check passed")
}

func (p *IpFinishOutput) Init(m *bpf.Module) error {
	return nil
}

func (p *IpFinishOutput) GetSource() string {
	src := source_ip_finish_output
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.IP_FINISH_OUTPUT), -1)
}

func (p *IpFinishOutput) GetProbePoint() (name string, probeType string) {
	return "ip_finish_output", plugin.KPROBE
}

func (p *IpFinishOutput) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpFinishOutput) NeedProbe() bool {
	return true
}
