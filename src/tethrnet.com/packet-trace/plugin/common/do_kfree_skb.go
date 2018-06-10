package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source___kfree_skb string = `
int kprobe____kfree_skb(struct pt_regs *ctx, struct sk_buff *skb){
	log_event_t event = {};
	event.skb_adr = (u64) skb;
	u8 is_exist = get_epoch(&event);

	if (is_exist==EXIST) {
		release_epoch(event.skb_adr);
		event.plugin = ___plugintype___;
		log_events.perf_submit(ctx, &event, sizeof(event));
	}
	return 0;
}

`

type DoKfreeSkb struct {
}

func (p *DoKfreeSkb) Init(m *bpf.Module) error {
	return nil
}

func (p *DoKfreeSkb) GetSource() string {
	src := source___kfree_skb
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.KFREE_SKB), -1)
}

func (p *DoKfreeSkb) GetProbePoint() (name string, probeType string) {
	return "__kfree_skb", plugin.KPROBE
}

func (p *DoKfreeSkb) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *DoKfreeSkb) NeedProbe() bool {
	return true
}

func (p *DoKfreeSkb) GetType() int {
	return plugin.DOKFREE_SKB
}

func (p *DoKfreeSkb) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "__kfree_skb, Dropped or Skb destroyed"
}
