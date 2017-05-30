package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_skb_release_all string = `
int kprobe__skb_release_all(struct pt_regs *ctx, struct sk_buff *skb){
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

type SkbReleaseAll struct {
}

func (p *SkbReleaseAll) Init(m *bpf.Module) error {
	return nil
}

func (p *SkbReleaseAll) GetSource() string {
	src := source_skb_release_all
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.SKB_FREE_ALL), -1)
}

func (p *SkbReleaseAll) GetProbePoint() (name string, probeType string) {
	return "skb_release_all", plugin.KPROBE
}

func (p *SkbReleaseAll) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *SkbReleaseAll) NeedProbe() bool {
	return true
}

func (p *SkbReleaseAll) GetType() int {
	return plugin.SKB_FREE_ALL
}

func (p *SkbReleaseAll) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "skb_release_all"
}
