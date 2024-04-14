package metric

import (
	"log"
	"os"
	"strings"
	"unicode"
)

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}

func (p *Prometheus) reload() {
	var fsTargetIP []string
	var fsTargetName []string

	fb, err := os.ReadFile("prometheus.conf")
	if err != nil {
		log.Printf("%v", err)
		return
	}

	fs := cutSpace(string(fb))

	if si := strings.Index(fs, "PromTargetIP=\""); si > -1 {
		s := si + len("PromTargetIP=\"")
		e := strings.Index(fs[s:], "\"")
		if e >= 7 {
			fsTargetIP = strings.Split(fs[s:s+e], ",")
		}
	}
	if si := strings.Index(fs, "PromTargetName=\""); si > -1 {
		s := si + len("PromTargetName=\"")
		e := strings.Index(fs[s:], "\"")
		if e > 0 {
			fsTargetName = strings.Split(fs[s:s+e], ",")
		}
	}

	if fsTargetIP != nil && fsTargetName != nil && len(fsTargetIP) == len(fsTargetName) {
		p.TargetConf.Lock()
		p.TargetIP = fsTargetIP
		p.TargetName = fsTargetName
		p.TargetEmpty = false
		p.TargetMap = make(map[string]string)
		for i := 0; i < len(p.TargetName); i++ {
			p.TargetMap[p.TargetIP[i]] = p.TargetName[i]
		}
		p.TargetConf.Unlock()
		log.Printf("successfully reloaded PromTargetIP: %#v", fsTargetIP)
		log.Printf("successfully reloaded PromTargetName: %#v", fsTargetName)
	} else {
		log.Printf("failed to reload PromTargetIP: %#v", fsTargetIP)
		log.Printf("failed to reload PromTargetName: %#v", fsTargetName)
		log.Printf("please give every PromTargetIP a unique IP and PromTargetName a unique name")
	}
}
