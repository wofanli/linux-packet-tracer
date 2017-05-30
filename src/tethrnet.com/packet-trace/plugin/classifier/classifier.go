package classifier

import (
	"C"
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"net"
	"strconv"
	"strings"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/util"
	"unsafe"
)

type sub_event_classifier struct {
	src, dst, rule_src, rule_dst uint32
}

var source_base string = `
/* 
 * Static inline is required.
 * Why?? maybe bpf prog canot invoke other func
 * return 0 to pass classify
 */
static inline int classify(u32 src, u32 dst) {
	if (___src___ !=0 && ((src&___src_mask___) != ___src___)) {
		return 1;	
	}
	if (___dst___ !=0 && ((dst&___dst_mask___) != ___dst___)) {
		return 1;
	}
	return 0;
}
`

type Classifier struct {
	srcIp  *net.IPNet
	dstIp  *net.IPNet
	source string
}

func NewClassifier(src, dst *net.IPNet) *Classifier {
	c := &Classifier{
		srcIp: src,
		dstIp: dst,
	}
	srcInt := strconv.Itoa(int(util.Ip2Int(c.srcIp.IP)))
	srcMask := strconv.Itoa(int(util.IPMask2Int(c.srcIp.Mask)))
	dstInt := strconv.Itoa(int(util.Ip2Int(c.dstIp.IP)))
	dstMask := strconv.Itoa(int(util.IPMask2Int(c.dstIp.Mask)))

	c.source = source_base
	c.source = strings.Replace(c.source, "___plugintype___", strconv.Itoa(plugin.CLASSIFIER), -1)
	c.source = strings.Replace(c.source, "___src___", srcInt, -1)
	c.source = strings.Replace(c.source, "___src_mask___", srcMask, -1)
	c.source = strings.Replace(c.source, "___dst___", dstInt, -1)
	c.source = strings.Replace(c.source, "___dst_mask___", dstMask, -1)
	return c
}
func (c *Classifier) Init(m *bpf.Module) error {
	return nil
}

func (c *Classifier) GetSource() string {
	return c.source
}

func (c *Classifier) GetProbePoint() (name string, probeType string) {
	return "", ""
}

func (c *Classifier) GetProbeName() string {
	return ""
}

func (c *Classifier) NeedProbe() bool {
	return false
}

func (c *Classifier) GetType() int {
	return plugin.CLASSIFIER
}

func (c *Classifier) Decode(d [plugin.MAX_MSG_LEN]byte) string {
	data := d[:]
	event := (*sub_event_classifier)(unsafe.Pointer(uintptr(C.CBytes(data))))
	return fmt.Sprintf("classifier:%x->%x, with rule: %x->%x",
		event.src, event.dst,
		event.rule_src, event.rule_dst)
}
