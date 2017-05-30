package route

import (
	"C"
	bpf "github.com/iovisor/gobpf/bcc"
	"tethrnet.com/packet-trace/plugin"
)

const source_fib_validate_source string = `

typedef struct {
	u64 skb;
	u64 iif;
	u32 src;
}fib_validate_source_cache_t;

BPF_HASH(fib_validate_source_cache, u32, fib_validate_source_cache_t);

typedef struct {
	u64 srcdev;
	u32 src;
	u32 rp_filter_chk;
}sub_event_fib_validate_source;

int kprobe__fib_validate_source(struct pt_regs *ctx, struct sk_buff *skb, 
							    u32 src, u32 dst, u8 tos, int oif, struct net_device *dev){
	u8 exist = is_skb_ontracked((u64)skb);

	if (exist==EXIST) {
		fib_validate_source_cache_t cache = {};
		cache.skb = (u64)skb;
		cache.src = src;
		cache.iif = dev->ifindex;
		u32 pid = bpf_get_current_pid_tgid();
		fib_validate_source_cache.update(&pid, &cache);
	}
	return 0;
}
`

type sub_event_fib_validate_source struct {
	indev         uint64
	src           uint32
	rp_filter_chk uint32
}

type FibValidateSource struct {
}

func (p *FibValidateSource) GetType() int {
	return plugin.FIB_VALIDATE_SOURCE
}

func (p *FibValidateSource) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return ""
}

func (p *FibValidateSource) Init(m *bpf.Module) error {
	return nil
}

func (p *FibValidateSource) GetSource() string {
	return source_fib_validate_source
}

func (p *FibValidateSource) GetProbePoint() (name string, probeType string) {
	return "fib_validate_source", plugin.KPROBE
}

func (p *FibValidateSource) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *FibValidateSource) NeedProbe() bool {
	return true
}
