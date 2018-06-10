package event

import (
	"C"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/util"
	"time"
	"unsafe"
)

type traceEvent struct {
	skbAdr uint64
	epoch  uint32
	plugin uint32
	id     uint32
	pid    uint32
	msg    [plugin.MAX_MSG_LEN]byte
}

type TraceEventKey struct {
	SkbAdr uint64
	Epoch  uint
}

type TraceEvent struct {
	TraceEventKey
	ProbePoint string
	PluginId   uint32
	Ts         time.Time
	Id         uint32
	Pid        uint32
	Msg        string
	Netns      string
	Cmd        string
}

func GenTraceEvent(raw []byte, pall *plugin.Plugins) *TraceEvent {
	_event := (*traceEvent)(unsafe.Pointer(uintptr(C.CBytes(raw))))
	event := TraceEvent{}
	event.SkbAdr = _event.skbAdr
	event.Epoch = uint(_event.epoch)
	event.Ts = time.Now()
	event.Id = _event.id
	event.Pid = _event.pid
	event.PluginId = _event.plugin
	event.Netns = util.Pid2Netns(int(event.Pid))
	event.Cmd = util.GetNameByPid(int(event.Pid))
	p := pall.Get(int(_event.plugin))
	if p == nil {
		return nil
	}
	event.ProbePoint = p.GetProbeName()
	event.Msg = p.Decode(_event.msg)
	return &event
}
