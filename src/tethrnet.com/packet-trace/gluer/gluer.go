package gluer

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/qiniu/log"
	"net"
	"tethrnet.com/packet-trace/agg"
	"tethrnet.com/packet-trace/event"
	"tethrnet.com/packet-trace/plugin"
	"tethrnet.com/packet-trace/plugin/classifier"
	"tethrnet.com/packet-trace/plugin/common"
	"tethrnet.com/packet-trace/plugin/ip"
	"tethrnet.com/packet-trace/plugin/iptables"
	"tethrnet.com/packet-trace/plugin/netfilter"
	"tethrnet.com/packet-trace/plugin/route"
	"tethrnet.com/packet-trace/plugin/tcp"
	"tethrnet.com/packet-trace/plugin/tunnel"
	"time"
)

type GluerConfig struct {
	MatchSrc *net.IPNet
	MatchDst *net.IPNet
	MaxPkts  int
	MaxDura  time.Duration
}

type Gluer struct {
	source  string
	module  *bpf.Module
	plugins *plugin.Plugins

	// log event perf map
	logEvent   *bpf.Table
	rawLogChan chan []byte
	perfMap    *bpf.PerfMap
	logChan    chan *event.TraceEvent
	Stop       chan bool
	hasStopped bool
	agger      *agg.Agg
	cfg        *GluerConfig
}

func NewGluer(cfg *GluerConfig) *Gluer {
	plugins := plugin.NewPlugins()
	plugins.Append(
		common.NewCommon(),
		classifier.NewClassifier(cfg.MatchSrc, cfg.MatchDst),
		&common.KfreeSkb{},
		&common.SkbReleaseAll{},
		&common.KfreeSkbPartial{},
		&common.ConsumeSkb{},
		&common.NapiConsumeSkb{},
		netfilter.NewNfHookSlow(),
		netfilter.NewNfHookSlowRet(),
		&ip.IpRecv{},
		&ip.IpRecvFinish{},
		&ip.IpQueueXmit{},
		&ip.IpFinishOutput{},
		&ip.IpForward{},
		&ip.IpForwardFinish{},
		&ip.IpSendSkb{},
		&ip.IpError{},
		&iptables.IptDoTable{},
		&iptables.IptDoTableRet{},
		&route.FibValidateSource{},
		&route.FibValidateSourceRet{},
		&route.IpRouteInputNoref{},
		&route.IpRouteInputNorefRet{},
		&tunnel.IpTunnelXmit{},
		&tcp.TcpV4Rcv{},
	)

	g := &Gluer{}
	g.plugins = plugins
	g.cfg = cfg
	g.Stop = make(chan bool, 1)
	return g
}

func (g *Gluer) Restart() {
	g.Close()
	g.Start()
}

func (g *Gluer) Start() {
	g.Stop = make(chan bool, 1)
	src, err := g.plugins.GetSource()
	if err != nil {
		log.Fatal("fail to get bpf src code", err)
	}
	log.Debug("source bpf code: ", src)
	g.source = src
	g.module = bpf.NewModule(g.source, []string{})
	if g.module == nil {
		log.Fatal("fail to new module")
	}
	g.initLogEvent()
	g.initCbPerPlugin()
	g.loadProbe()
}

func (g *Gluer) GetLogChan() chan *event.TraceEvent {
	return g.logChan
}

func (g *Gluer) Close() {
	log.Info("Gluer is closing")
	g.perfMap.Stop()
	log.Info("Perf Map stopped")
	g.module.Close()
	log.Info("module closed")
	g.hasStopped = true
	g.Stop <- true
}

func (g *Gluer) IsStopped() bool {
	return g.hasStopped
}

func (g *Gluer) loadProbe() {
	for _, p := range g.plugins.Apis {
		if !p.NeedProbe() {
			continue
		}
		probePoint, probeType := p.GetProbePoint()

		probe, err := g.module.LoadKprobe(p.GetProbeName())
		if err != nil {
			log.Error("LoadKprobe fails", p.GetProbeName(), err)
		} else {
			switch probeType {
			case plugin.KPROBE:
				err = g.module.AttachKprobe(probePoint, probe)
			case plugin.KRETPROBE:
				err = g.module.AttachKretprobe(probePoint, probe)
			default:
				log.Error("unsupported probeType", p.GetProbeName())
			}
			if err != nil {
				log.Error("Attach probe fails", p.GetProbeName(), err)
			}
		}
	}
}

func (g *Gluer) initCbPerPlugin() {
	for _, p := range g.plugins.Apis {
		err := p.Init(g.module)
		if err != nil {
			log.Error("fail to Init", p.GetProbeName, err)
		}
	}
}

func (g *Gluer) GetResultsCnt() int {
	results := g.agger.GetResults()
	return len(results)
}

func (g *Gluer) GetResults() []agg.TraceEventPerPacket {
	return g.agger.GetResults()
}

func (g *Gluer) GetResulbByIdx(i int) agg.TraceEventPerPacket {
	return g.agger.GetResulbByIdx(i)
}

func (g *Gluer) ResetIdx() {
	g.agger.ResetIdx()
}

func (g *Gluer) GetNextResult() (agg.TraceEventPerPacket, error) {
	return g.agger.GetNextResult()
}

func (g *Gluer) initLogEvent() {
	var err error
	g.rawLogChan = make(chan []byte, 1000)
	g.logChan = make(chan *event.TraceEvent, 1000)
	g.logEvent = bpf.NewTable(g.module.TableId(common.LOG_EVENT_TBL), g.module)
	g.perfMap, err = bpf.InitPerfMap(g.logEvent, g.rawLogChan)
	if err != nil {
		log.Fatal("fail to initLogEvent", err)
	}

	aggCfg := &agg.AggConfig{
		C:       g.logChan,
		MaxDura: g.cfg.MaxDura,
		MaxPkts: g.cfg.MaxPkts,
	}
	g.agger = agg.NewAgg(aggCfg)
	go g.agger.Run()

	g.perfMap.Start()
	go func() {
		for {
			select {
			case <-g.agger.Stop:
				g.Close()
				log.Info("agger stoped")
				return
			case raw := <-g.rawLogChan:
				e := event.GenTraceEvent(raw, g.plugins)
				if e != nil {
					g.logChan <- e
				}
			}
		}
	}()
}
