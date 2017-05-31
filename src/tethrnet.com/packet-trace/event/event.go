package event

import (
	"C"
	"tethrnet.com/packet-trace/plugin"
	"time"
	"unsafe"
)

type traceEvent struct {
	skbAdr uint64
	epoch  uint32
	plugin uint32
	id     uint32
	pad    uint32
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
	Msg        string
}

func GenTraceEvent(raw []byte, pall *plugin.Plugins) *TraceEvent {
	_event := (*traceEvent)(unsafe.Pointer(uintptr(C.CBytes(raw))))
	event := TraceEvent{}
	event.SkbAdr = _event.skbAdr
	event.Epoch = uint(_event.epoch)
	event.Ts = time.Now()
	event.Id = _event.id
	event.PluginId = _event.plugin
	p := pall.Get(int(_event.plugin))
	if p == nil {
		return nil
	}
	event.ProbePoint = p.GetProbeName()
	event.Msg = p.Decode(_event.msg)
	return &event
}
