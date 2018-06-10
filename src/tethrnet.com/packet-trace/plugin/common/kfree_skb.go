package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_kfree_skb string = `
int kprobe__kfree_skb(struct pt_regs *ctx, struct sk_buff *skb){
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

type KfreeSkb struct {
}

func (p *KfreeSkb) Init(m *bpf.Module) error {
	return nil
}

func (p *KfreeSkb) GetSource() string {
	src := source_kfree_skb
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.KFREE_SKB), -1)
}

func (p *KfreeSkb) GetProbePoint() (name string, probeType string) {
	return "kfree_skb", plugin.KPROBE
}

func (p *KfreeSkb) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *KfreeSkb) NeedProbe() bool {
	return true
}

func (p *KfreeSkb) GetType() int {
	return plugin.KFREE_SKB
}

func (p *KfreeSkb) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "Dropped or Skb destroyed"
}
