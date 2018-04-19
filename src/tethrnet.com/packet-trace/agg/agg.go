package agg

import (
	"errors"
	"fmt"
	"github.com/qiniu/log"
	"sort"
	"tethrnet.com/packet-trace/event"
	"tethrnet.com/packet-trace/plugin"
	"time"
)

const (
	AggInit = iota
	AggStarted
	AggFinished
)

const (
	DftMaxPkts = 512
	DftMaxDura = time.Second * 5
)

type TraceEventPerPacket []*event.TraceEvent

func (a TraceEventPerPacket) Len() int      { return len(a) }
func (a TraceEventPerPacket) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a TraceEventPerPacket) Less(i, j int) bool {
	return a[i].Id < a[j].Id
}

func (t TraceEventPerPacket) String() string {
	str := ""
	events := ([]*event.TraceEvent)(t)
	for _, e := range events {
		comp := plugin.PluginId2Str(e.PluginId)
		if comp != "" {
			str += fmt.Sprintf("%d,%s (%s) :\n", e.Id, comp, e.ProbePoint)
		} else {
			str += fmt.Sprintf("%d,%s:\n", e.Id, e.ProbePoint)
		}
		str += fmt.Sprintf("    %v\n", e.Msg)
	}
	return str
}

type Agg struct {
	logChan chan *event.TraceEvent

	cacheMap map[event.TraceEventKey][]*event.TraceEvent
	result   []TraceEventPerPacket
	currIdx  int
	start    time.Time
	maxDura  time.Duration
	maxPkt   int
	status   int
	Stop     chan bool
}

type AggConfig struct {
	C       chan *event.TraceEvent
	MaxPkts int
	MaxDura time.Duration
}

func NewAgg(cfg *AggConfig) *Agg {
	a := &Agg{
		logChan:  cfg.C,
		status:   AggInit,
		currIdx:  0,
		cacheMap: make(map[event.TraceEventKey][]*event.TraceEvent),
		Stop:     make(chan bool, 1),
	}
	if cfg.MaxPkts > 0 {
		a.maxPkt = cfg.MaxPkts
	} else {
		a.maxPkt = DftMaxPkts
	}
	if cfg.MaxDura > 0 {
		a.maxDura = cfg.MaxDura
	} else {
		a.maxDura = DftMaxDura
	}
	return a
}

type aggResult []TraceEventPerPacket

func (a aggResult) Len() int      { return len(a) }
func (a aggResult) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a aggResult) Less(i, j int) bool {
	tsa := ([]*event.TraceEvent)(a[i])[0].Ts
	tsb := ([]*event.TraceEvent)(a[j])[0].Ts
	return tsb.After(tsa)
}
func (a *Agg) stop() {
	log.Debug("a.stop", len(a.cacheMap))
	a.status = AggFinished
	a.result = make([]TraceEventPerPacket, len(a.cacheMap))
	idx := 0
	for _, cache := range a.cacheMap {
		sort.Sort(TraceEventPerPacket(cache))
		for eventIdx := 0; eventIdx < len(cache); eventIdx++ {
			if cache[eventIdx].PluginId == plugin.IP_ERROR && eventIdx > 0 &&
				(cache[eventIdx-1].PluginId == plugin.IP_ROUTE_INPUT_NOREF ||
					cache[eventIdx-1].PluginId == plugin.IP_ROUTE_INPUT_NOREF_RET) {
				cache[eventIdx].Msg += " Check route table & ipv4_forward config."
			}
		}
		a.result[idx] = TraceEventPerPacket(cache)
		idx++
	}
	sort.Sort(aggResult(a.result))
	a.Stop <- true
}

func (a *Agg) GetResults() []TraceEventPerPacket {
	return ([]TraceEventPerPacket)(a.result)
}

var (
	NullTraceEventPerPacket = []*event.TraceEvent{}
	EOF                     = errors.New("EoF")
)

func (a *Agg) GetResulbByIdx(i int) TraceEventPerPacket {
	if i < len(a.result) {
		return a.result[i]
	} else {
		return NullTraceEventPerPacket
	}
}

func (a *Agg) ResetIdx() {
	a.currIdx = 0
}

func (a *Agg) GetNextResult() (TraceEventPerPacket, error) {
	if a.currIdx < len(a.result) {
		idx := a.currIdx
		a.currIdx++
		return a.result[idx], nil
	}
	a.currIdx = 0
	return NullTraceEventPerPacket, EOF
}

func (a *Agg) Run() {
	log.Info("Agg Run starts")
	a.start = time.Now()
	maxDuraTimer := time.NewTimer(a.maxDura)
	buffFullTimer := time.NewTimer(a.maxDura * 10)
	a.status = AggStarted
	defer a.stop()
	for {
		select {
		case <-maxDuraTimer.C:
			return
		case <-buffFullTimer.C:
			return
		default:
		}

		select {
		case e := <-a.logChan:
			log.Debug("got a raw event log", e)
			key := event.TraceEventKey{
				SkbAdr: e.SkbAdr,
				Epoch:  e.Epoch,
			}
			logs, ok := a.cacheMap[key]
			if !ok {
				if len(a.cacheMap) < a.maxPkt {
					logs = []*event.TraceEvent{e}
					a.cacheMap[key] = logs
				} else {
					// Assume 1 second is enough for the last packet to finish
					buffFullTimer.Reset(time.Second)
				}
			} else {
				logs = append(logs, e)
				a.cacheMap[key] = logs
			}
		case <-maxDuraTimer.C:
			return
		case <-buffFullTimer.C:
			return
		}
	}
}
