package monotonic

import (
	"time"
)

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

func GetTime() (uint64, int64) {
	monotonic := uint64(C.get_nsecs())
	timestamp := time.Now().UTC().UnixNano()
	return monotonic, timestamp
}

func GetRealTime(capTime uint64) time.Time {
	monotonic := uint64(C.get_nsecs())
	timestamp := time.Now().UTC().UnixNano()
	return time.Unix(0, (timestamp - int64(monotonic-capTime)))
}
