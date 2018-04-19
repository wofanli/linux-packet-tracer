package main

import (
	"fmt"
	"github.com/abiosoft/ishell"
	"github.com/qiniu/log"
	"net"
	"strconv"
	"tethrnet.com/packet-trace/agg"
	"tethrnet.com/packet-trace/gluer"
	"time"
)

type config struct {
	shell     *ishell.Shell
	gluer     *gluer.Gluer
	src       *net.IPNet
	dst       *net.IPNet
	debug     int
	maxPkt    int
	maxDura   time.Duration
	isStarted bool
}

func initConfig() *config {
	cfg := &config{}
	cfg.reset()

	cfg.shell = ishell.New()
	cfg.shell.Println(`Welcome to Packet Tracing for Linux`)
	cfg.appendShow()
	cfg.appendMatch()
	cfg.appendDebug()
	cfg.appendMaxPkt()
	cfg.appendMaxDuration()
	cfg.appendStartCmd()
	cfg.appendRestartCmd()
	cfg.appendWaitCmd()
	cfg.createGluer()
	return cfg
}

func (cfg *config) createGluer() {
	gluerCfg := &gluer.GluerConfig{
		MatchSrc: cfg.src,
		MatchDst: cfg.dst,
		MaxPkts:  cfg.maxPkt,
		MaxDura:  cfg.maxDura,
	}
	cfg.gluer = gluer.NewGluer(gluerCfg)
}
func (cfg *config) reset() {
	cfg.debug = log.Linfo
	cfg.src = &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.IPv4Mask(0, 0, 0, 0),
	}
	cfg.dst = &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.IPv4Mask(0, 0, 0, 0),
	}
	cfg.maxDura = agg.DftMaxDura
	cfg.maxPkt = agg.DftMaxPkts
}

func (cfg *config) appendWaitCmd() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "wait",
		Func: func(c *ishell.Context) {
			c.Println("waiting for the tracing to finished")
			<-cfg.gluer.Stop
		},
		Help: "wait until the tracing ends",
	})
}

func (cfg *config) appendStartCmd() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "start",
		Func: func(c *ishell.Context) {
			if cfg.isStarted == false {
				cfg.createGluer()
				cfg.gluer.Start()
				cfg.isStarted = true
			} else {
				c.Println("tracer has been started. Use restart if you would like to restart it")
			}
		},
		Help: "start to trace packet",
	})
}

func (cfg *config) appendRestartCmd() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "restart",
		Func: func(c *ishell.Context) {
			cfg.createGluer()
			cfg.gluer.Start()
		},
		Help: "restart packet tracing",
	})
}

func (cfg *config) setMatchSrc(str string) error {
	_, netmask, err := net.ParseCIDR(str)
	if err != nil {
		log.Error("fail to parse netmask", str, err)
		return err
	}
	cfg.src = netmask
	return nil
}

func (cfg *config) setMatchDst(str string) error {
	_, netmask, err := net.ParseCIDR(str)
	if err != nil {
		log.Error("fail to parse netmask", str, err)
		return err
	}
	cfg.dst = netmask
	return nil
}

func (cfg *config) appendMatch() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "src",
		Help: "src ip, like 1.2.3.0/24",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("Must look like: match src 1.2.3.0/24")
				return
			}
			cfg.setMatchSrc(c.Args[0])
		}})
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "dst",
		Help: "dst ip, like 1.2.3.0/24",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("Must look like: match dst 1.2.3.0/24")
				return
			}
			cfg.setMatchDst(c.Args[0])
		}})
}

func (cfg *config) appendMaxDuration() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "max_duration",
		Help: "set max seconds to keep tracing, (1~60)",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("Use cli like: max_duration xxx")
				return
			}
			num, err := strconv.Atoi(c.Args[0])
			if err != nil {
				c.Println("Use cli like: max_duration xxx", err)
				return
			}
			if num < 1 || num > 60 {
				c.Println("the range should be 1~60")
				return
			}
			cfg.maxDura = time.Second * time.Duration(num)
		}})
}

func (cfg *config) appendMaxPkt() {
	cfg.shell.AddCmd(&ishell.Cmd{
		Name: "max_pkt",
		Help: "set max pkt to cached, (1~2048)",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("Use cli like: max_pkt xxx")
				return
			}
			num, err := strconv.Atoi(c.Args[0])
			if err != nil {
				c.Println("Use cli like: max_pkt xxx", err)
				return
			}
			if num < 1 || num > 2048 {
				c.Println("The range should be 1~2048")
				return
			}
			cfg.maxPkt = num
		}})
}

func (cfg *config) appendDebug() {
	cmd := (&ishell.Cmd{
		Name: "debug",
		Help: "set debue level (debug, info, warn, error) ",
	})
	cmd.AddCmd(&ishell.Cmd{
		Name: "debug",
		Help: "debug < info < warn < error",
		Func: func(c *ishell.Context) {
			cfg.debug = log.Ldebug
			log.SetOutputLevel(cfg.debug)
		}})
	cmd.AddCmd(&ishell.Cmd{
		Name: "info",
		Help: "debug < info < warn < error",
		Func: func(c *ishell.Context) {
			cfg.debug = log.Linfo
			log.SetOutputLevel(cfg.debug)
		}})
	cmd.AddCmd(&ishell.Cmd{
		Name: "warn",
		Help: "debug < info < warn < error",
		Func: func(c *ishell.Context) {
			cfg.debug = log.Lwarn
			log.SetOutputLevel(cfg.debug)
		}})
	cmd.AddCmd(&ishell.Cmd{
		Name: "error",
		Help: "debug < info < warn < error",
		Func: func(c *ishell.Context) {
			cfg.debug = log.Lerror
			log.SetOutputLevel(cfg.debug)
		}})
	cfg.shell.AddCmd(cmd)
}

func (cfg *config) appendShow() {
	show := (&ishell.Cmd{
		Name: "show",
		Func: func(c *ishell.Context) {
			if len(c.Args) != 1 {
				c.Println("the cli should be some thing like: show 1")
				return
			}
			if cfg.gluer.IsStopped() == false {
				c.Println("tracing has not been done")
				return
			}

			idx, err := strconv.Atoi(c.Args[0])
			if err != nil {
				c.Println(err)
				return
			}
			packet := cfg.gluer.GetResulbByIdx(idx)
			c.Println(packet)
		},
		Help: "show the output",
	})

	show.AddCmd(&ishell.Cmd{
		Name: "all",
		Help: "show all the traced packets",
		Func: func(c *ishell.Context) {
			if cfg.gluer == nil {
				c.Println("tracing has not been started yet")
				return
			}
			if cfg.gluer.IsStopped() == false {
				c.Println("tracing has not been done")
				return
			}
			cfg.gluer.ResetIdx()
			for {
				packet, err := cfg.gluer.GetNextResult()
				if err == nil {
					c.Println("******************")
					c.Println(packet)
				} else {
					return
				}
			}
		}})
	show.AddCmd(&ishell.Cmd{
		Name: "summary",
		Help: "show summary of traced packets",
		Func: func(c *ishell.Context) {
			c.Printf("The number of packets we traced is: %d\n",
				cfg.gluer.GetResultsCnt())
		},
	})
	show.AddCmd(&ishell.Cmd{
		Name: "config",
		Help: "show tracer config",
		Func: func(c *ishell.Context) {
			c.Println("match rules: ")
			c.Printf("    dst: %v, src: %v\n",
				cfg.dst, cfg.src)
			c.Println("tracer parameters: ")
			c.Printf("    debug level:%v\n",
				dbgLvl2Str(cfg.debug))
			c.Printf("    max packets: %d\n",
				cfg.maxPkt)
			c.Printf("    max duration: %v\n",
				cfg.maxDura)
		},
	})
	cfg.shell.AddCmd(show)
}

func dbgLvl2Str(dbg int) string {
	switch dbg {
	case 0:
		return "debug"
	case 1:
		return "info"
	case 2:
		return "warn"
	case 3:
		return "error"
	}
	log.Error("opps, what the hell of the debug level", dbg)
	return fmt.Sprintf("invalid debug level %d", dbg)
}
