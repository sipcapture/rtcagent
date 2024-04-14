package metric

import (
	"fmt"
	"strconv"
	"strings"
)

var (
	errNoComma  = fmt.Errorf("no comma in string")
	errNoTwoVal = fmt.Errorf("no two values in string")
)

func (p *Prometheus) dissectRTCPXRStats(nodeID string, stats *string) {

	fmt.Println("dissectRTCPXRStats: ", nodeID, stats)
}

func normMax(val float64) float64 {
	if val > 10000000 {
		return 0
	}
	return val
}

func splitCommaInt(str string) (int, int, error) {
	var err error
	var one, two int
	sp := strings.IndexRune(str, ',')
	if sp == -1 {
		return one, two, errNoComma
	}

	if one, err = strconv.Atoi(str[0:sp]); err != nil {
		return one, two, err
	}
	if len(str)-1 >= sp+1 {
		if two, err = strconv.Atoi(str[sp+1:]); err != nil {
			return one, two, err
		}
	} else {
		return one, two, errNoTwoVal
	}
	return one, two, nil
}
