package event_processor

import (
	"io"
	"log"
	"testing"
)

func TestWriteDropsEventsWhenQueueIsFull(t *testing.T) {
	ep := NewEventProcessor(log.New(io.Discard, "", 0), false)

	for i := 0; i < MaxIncomingChanLen; i++ {
		ep.Write(nil)
	}
	if got := ep.Dropped(); got != 0 {
		t.Fatalf("unexpected drops while filling the queue: %d", got)
	}

	// The queue is full: further writes must not block and must be counted.
	ep.Write(nil)
	ep.Write(nil)

	if got := ep.Dropped(); got != 2 {
		t.Fatalf("expected 2 dropped events, got %d", got)
	}
}
