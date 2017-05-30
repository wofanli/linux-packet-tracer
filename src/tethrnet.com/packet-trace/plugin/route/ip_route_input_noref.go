package route

import (
	"C"
	bpf "github.com/iovisor/gobpf/bcc"
	"tethrnet.com/packet-trace/plugin"
)

const source_ip_route_input_noref string = `

typedef struct {
	u64 skb;
	u32 src;
	u32 dst;
	u64 iif;
}ip_route_input_noref_cache_t;

BPF_HASH(ip_route_input_noref_cache, u32, ip_route_input_noref_cache_t);

typedef struct {
	u64 iif;
	u32 src;
	u32 dst;
	u32  err;
}sub_event_ip_route_input_noref;

int kprobe__ip_route_input_noref(struct pt_regs *ctx, struct sk_buff *skb, 
							    u32 dst, u32 src, u8 tos, struct net_device *dev){
	u8 exist = is_skb_ontracked((u64)skb);

	if (exist==EXIST) {
		ip_route_input_noref_cache_t cache = {};
		cache.skb = (u64)skb;
		cache.src = src;
		cache.dst = dst;
		cache.iif = dev->ifindex;
		u32 pid = bpf_get_current_pid_tgid();
		ip_route_input_noref_cache.update(&pid, &cache);
	}
	return 0;
}
`

type sub_event_ip_route_input_noref struct {
	iif uint64
	src uint32
	dst uint32
	err uint32
}

type IpRouteInputNoref struct {
}

func (p *IpRouteInputNoref) GetType() int {
	return plugin.IP_ROUTE_INPUT_NOREF
}

func (p *IpRouteInputNoref) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return ""
}

func (p *IpRouteInputNoref) Init(m *bpf.Module) error {
	return nil
}

func (p *IpRouteInputNoref) GetSource() string {
	return source_ip_route_input_noref
}

func (p *IpRouteInputNoref) GetProbePoint() (name string, probeType string) {
	return "ip_route_input_noref", plugin.KPROBE
}

func (p *IpRouteInputNoref) GetProbeName() string {
	name, t := p.GetProbePoint()
	return t + "__" + name
}

func (p *IpRouteInputNoref) NeedProbe() bool {
	return true
}
