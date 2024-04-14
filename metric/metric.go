package metric

import (
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

type Metric struct {
	H    MetricHandler
	Chan chan *string
	quit chan bool
}

type MetricHandler interface {
	setup() error
	reload()
	expose(chan *string)
}

func New(name string) *Metric {
	var register = map[string]MetricHandler{
		"prometheus": new(Prometheus),
	}

	return &Metric{
		H:    register[name],
		quit: make(chan bool),
	}
}

func (m *Metric) Run() error {
	err := m.H.setup()
	if err != nil {
		return err
	}

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			m.H.expose(m.Chan)
		}()
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-s:
				m.H.reload()
			case <-m.quit:
				m.quit <- true
				return
			}
		}
	}()

	return nil
}

func (m *Metric) End() {
	m.quit <- true
	<-m.quit
	close(m.Chan)
	log.Printf("close metric channel")
}
