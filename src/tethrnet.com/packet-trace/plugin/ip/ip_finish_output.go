package ip

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"unsafe"
)

const source_ip_finish_output string = `
typedef struct {
	u32 mark;
} sub_event_ip_finish_output_t;

int kprobe__ip_finish_output(struct pt_regs *ctx,struct net *net, struct sock *sk, struct sk_buff *skb){
	log_event_t event = {};
	sub_event_ip_finish_output_t *subevent = (sub_event_ip_finish_output_t*)event.desc;

	event.skb_adr = (u64)skb;
	u8 exist = get_epoch(&event);
	event.plugin = ___plugintype___;
	subevent->mark = skb->mark;
	if (exist==EXIST) {
	  log_events.perf_submit(ctx,&event, sizeof(event));
	}
	return 0;
}
`

type sub_event_ip_finish_output_t struct {
	mark uint32
}

type IpFinishOutput struct {
}

func (p *IpFinishOutput) GetType() int {
	return plugin.IP_FINISH_OUTPUT
}

func (p *IpFinishOutput) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_ip_finish_output_t)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("POST_ROUTING check passed, mark:0x%x", event.mark)
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
