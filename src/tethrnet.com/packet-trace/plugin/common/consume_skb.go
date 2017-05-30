package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_consume_skb string = `
int kprobe__consume_skb(struct pt_regs *ctx, struct sk_buff *skb){
	log_event_t event = {};
	event.skb_adr = (u64) skb;
	u8 is_exist = get_epoch(event.skb_adr,&event.epoch, &event.id);

	if (is_exist==EXIST) {
		release_epoch(event.skb_adr);
		event.plugin = ___plugintype___;
		log_events.perf_submit(ctx, &event, sizeof(event));
	}
	return 0;
}

`

type ConsumeSkb struct {
}

func (p *ConsumeSkb) Init(m *bpf.Module) error {
	return nil
}

func (p *ConsumeSkb) GetSource() string {
	src := source_consume_skb
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.CONSUME_SKB), -1)
}

func (p *ConsumeSkb) GetProbePoint() (name string, probeType string) {
	return "consume_skb", plugin.KPROBE
}

func (p *ConsumeSkb) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *ConsumeSkb) NeedProbe() bool {
	return true
}

func (p *ConsumeSkb) GetType() int {
	return plugin.CONSUME_SKB
}

func (p *ConsumeSkb) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "Consumed Skb"
}
