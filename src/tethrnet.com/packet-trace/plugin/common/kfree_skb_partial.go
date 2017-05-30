package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_kfree_skb_partial string = `
int kprobe__kfree_skb_partial(struct pt_regs *ctx, struct sk_buff *skb){
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

type KfreeSkbPartial struct {
}

func (p *KfreeSkbPartial) Init(m *bpf.Module) error {
	return nil
}

func (p *KfreeSkbPartial) GetSource() string {
	src := source_kfree_skb_partial
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.KFREE_SKB_PARTIAL), -1)
}

func (p *KfreeSkbPartial) GetProbePoint() (name string, probeType string) {
	return "kfree_skb_partial", plugin.KPROBE
}

func (p *KfreeSkbPartial) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *KfreeSkbPartial) NeedProbe() bool {
	return true
}

func (p *KfreeSkbPartial) GetType() int {
	return plugin.KFREE_SKB_PARTIAL
}

func (p *KfreeSkbPartial) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "KfreeSkbPartial"
}
