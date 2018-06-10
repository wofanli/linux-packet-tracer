package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
)

const source_napi_consume_skb string = `
int kprobe__napi_consume_skb(struct pt_regs *ctx, struct sk_buff *skb){
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

type NapiConsumeSkb struct {
}

func (p *NapiConsumeSkb) Init(m *bpf.Module) error {
	return nil
}

func (p *NapiConsumeSkb) GetSource() string {
	src := source_napi_consume_skb
	return strings.Replace(src, "___plugintype___", strconv.Itoa(plugin.CONSUME_SKB), -1)
}

func (p *NapiConsumeSkb) GetProbePoint() (name string, probeType string) {
	return "napi_consume_skb", plugin.KPROBE
}

func (p *NapiConsumeSkb) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}
func (p *NapiConsumeSkb) NeedProbe() bool {
	return true
}

func (p *NapiConsumeSkb) GetType() int {
	return plugin.NAPI_CONSUME_SKB
}

func (p *NapiConsumeSkb) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return "Napi Consumed Skb"
}
