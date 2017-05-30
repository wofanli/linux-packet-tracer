package common

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/util"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <net/inet_sock.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>

typedef struct {
	uint64_t skb_adr;
	uint32_t epoch;
	uint32_t plugin;
	uint32_t id;
	uint32_t pad;
	char desc[___MAX_MSG_LEN___];
} log_event_t;

BPF_PERF_OUTPUT(log_events);

#define EPOCH 0
#define MAX_GSTATUS 1
BPF_TABLE("array", int, u32, gstatus, MAX_GSTATUS);

#define NOT_TRACK 0
#define MIN_EPOCH 1
#define MAX_EPOCH 1024

static inline u32 epoch_inc(){
	int key = EPOCH;
	u32 curr=0;
	u32 *epoch = gstatus.lookup(&key);
	
	if (epoch) {
		curr = *epoch;
		(*epoch)++;
	}
	return curr;
}

typedef struct {
	u32 epoch;
	u32 next_id;
}skb_status_t;

BPF_HASH(skb_status, u64, skb_status_t);

#define NEW 1
#define EXIST 0
// return 0 if existing skb. 
// will create skb if not existing
// otherwise it is a new skb
static inline u8 gen_epoch(u64 skb, u32 *e, u32 *id) {
	u64 key = skb;
	skb_status_t *val = skb_status.lookup(&key);
	if (!val) {
		skb_status_t s;
		s.epoch = epoch_inc();
		s.next_id = 1;
		skb_status.update(&key, &s);
		*e = s.epoch;
		*id = 0;
		return NEW;
	} else {
		*e = val->epoch;
		*id = val->next_id;
		val->next_id++;
		return EXIST;
	}
}

static inline u8 is_skb_ontracked(u64 skb) {
	u64 key = skb;
	skb_status_t *val = skb_status.lookup(&key);
	if (!val) {
		return NEW;
	} else {
		return EXIST;
	}
}

// return 0 if existing skb.
// will no create skb if not existing 
static inline u8 get_epoch(u64 skb, u32 *e, u32 *id) {
	u64 key = skb;
	skb_status_t *val = skb_status.lookup(&key);
	if (!val) {
		return NEW;
	} else {
		*e = val->epoch;
		*id = val->next_id;
		val->next_id++;
		return EXIST;
	}
}

static inline u8 release_epoch(u64 skb) {
	u64 key = skb;
	skb_status.delete(&key);
	return 0;
}

static inline u32 get_sip_from_sock(struct sock *sk) {
	u32 ip = 0;
	bpf_probe_read(&ip, sizeof(ip), &((struct inet_sock*)sk)->inet_saddr);
	return ip;
}
static inline u32 get_dip_from_sock(struct sock *sk) {
	u32 ip = 0;
	bpf_probe_read(&ip, sizeof(ip), &((struct inet_sock*)sk)->inet_daddr);
	return ip;
}


static inline u32 get_sip_from_skb(struct sk_buff *skb) {
	u32 ip = 0;
	bpf_probe_read(&ip, sizeof(ip), &((struct inet_sock*)skb)->inet_saddr);
	return ip;
}
static inline u32 get_dip_from_skb(struct sk_buff *skb) {
	u32 ip = 0;
	bpf_probe_read(&ip, sizeof(ip), &((struct inet_sock*)skb)->inet_daddr);
	return ip;
}

typedef struct {
	u8 ver_ihl;
	u8 tos;
	u16 tot_len;
	u16 id;
	u16 frag_off;
	u8 ttl;
	u8 prot;
	u16 checksum;
	u32 saddr;
	u32 daddr;
} ip_hdr;

`
const (
	LOG_EVENT_TBL = "log_events"
	GSTATUS_TBL   = "gstatus"
)
const (
	NOT_TRACK = 0
	MIN_EPOCH = 1
	MAX_EPOCH = 1024
)
const (
	STATUS_EPOCH = iota
)

type Common struct {
	interfaces map[int]string
}

var CommonInst *Common

func NewCommon() *Common {
	CommonInst = &Common{
		interfaces: util.GetInterfaces(),
	}
	return CommonInst
}

func (p *Common) GetIntf(index int) string {
	intf, ok := p.interfaces[index]
	if !ok {
		return "unknown"
	} else {
		return intf
	}
}

func (p *Common) Init(m *bpf.Module) error {
	gstatusMap := bpf.NewTable(m.TableId(GSTATUS_TBL), m)
	gstatusMap.Set(strconv.Itoa(STATUS_EPOCH), strconv.Itoa(MIN_EPOCH))
	return nil
}

func (p *Common) GetSource() string {
	src := source
	return strings.Replace(src, "___MAX_MSG_LEN___", strconv.Itoa(plugin.MAX_MSG_LEN), -1)
}

func (p *Common) GetProbePoint() (name string, probeType string) {
	return "", ""
}

func (p *Common) GetProbeName() string {
	return ""
}
func (p *Common) NeedProbe() bool {
	return false
}

func (p *Common) GetType() int {
	return plugin.COMMON
}

func (p *Common) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	return ""
}
