package event_processor

import (
	"bytes"
	"errors"
	"testing"
)

// fakeParser matches payloads that start with a given prefix.
type fakeParser struct {
	name   string
	prefix string
	buf    bytes.Buffer
	done   bool
}

func (f *fakeParser) detect(b []byte) error {
	if bytes.HasPrefix(b, []byte(f.prefix)) {
		return nil
	}
	return errors.New("payload does not match")
}

func (f *fakeParser) Write(b []byte) (int, error) {
	f.done = true
	return f.buf.Write(b)
}

func (f *fakeParser) ParserType() ParserType { return ParserTypeNull }
func (f *fakeParser) PacketType() PacketType { return PacketTypeNull }
func (f *fakeParser) Name() string           { return f.name }
func (f *fakeParser) IsDone() bool           { return f.done }
func (f *fakeParser) Init()                  { f.buf.Reset() }
func (f *fakeParser) Display() []byte        { return f.buf.Bytes() }
func (f *fakeParser) Reset()                 { f.done = false; f.buf.Reset() }

func TestNewParserSelectsDetectedParser(t *testing.T) {
	p := &fakeParser{name: "fake-test-parser", prefix: "FAKE"}
	Register(p)
	t.Cleanup(func() { delete(parsers, p.name) })

	got := NewParser([]byte("FAKEpayload"))
	if got != IParser(p) {
		t.Fatalf("expected the detected parser %q, got %T", p.name, got)
	}
}

func TestNewParserFallsBackToDefault(t *testing.T) {
	got := NewParser([]byte("this payload matches no registered parser"))
	if _, ok := got.(*DefaultParser); !ok {
		t.Fatalf("expected DefaultParser, got %T", got)
	}

	empty := NewParser(nil)
	if empty == nil {
		t.Fatal("expected a parser for an empty payload")
	}
	if _, ok := empty.(*DefaultParser); !ok {
		t.Fatalf("expected DefaultParser for an empty payload, got %T", empty)
	}
}
