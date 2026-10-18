package hepclient

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"rtcagent/pkg/metrics"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultMaxRetries = 5
	defaultBackoff    = 200 * time.Millisecond
	defaultMaxBackoff = 5 * time.Second
)

type HEPConn struct {
	conn   net.Conn
	writer *bufio.Writer
	errCnt uint
}

type HepClient struct {
	hepQueue  chan []byte
	addr      string
	transport string
	tlsConfig *tls.Config

	// retry policy for reconnecting after a failed send
	maxRetries int
	backoff    time.Duration
	maxBackoff time.Duration

	mu     sync.Mutex
	client HEPConn
}

// Option customises the behaviour of a HepClient.
type Option func(*HepClient)

// WithTLSConfig sets the TLS configuration used for the "tls" transport.
// Certificate verification is always performed unless the caller explicitly
// opts out, so the supplied configuration should normally only be used to
// provide a custom root CA or an explicit server name.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(h *HepClient) {
		h.tlsConfig = cfg
	}
}

// WithRetryPolicy configures how the client behaves when a send fails: it makes
// up to maxRetries reconnection attempts, waiting backoff before the first one
// and doubling the delay (capped at maxBackoff) between attempts. A
// non-positive maxRetries disables reconnection.
func WithRetryPolicy(maxRetries int, backoff, maxBackoff time.Duration) Option {
	return func(h *HepClient) {
		h.maxRetries = maxRetries
		if backoff > 0 {
			h.backoff = backoff
		}
		if maxBackoff > 0 {
			h.maxBackoff = maxBackoff
		}
	}
}

// defaultTLSConfig returns a TLS client configuration that verifies the
// server certificate chain and host name against the system trust store.
func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

func NewHepClient(addr, port, trans string, opts ...Option) (*HepClient, error) {

	h := &HepClient{
		addr:       strings.ToLower(cutSpace(addr + ":" + port)),
		client:     HEPConn{},
		transport:  trans,
		hepQueue:   make(chan []byte, 20000),
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
		maxBackoff: defaultMaxBackoff,
	}

	for _, opt := range opts {
		opt(h)
	}

	if err := h.ConnectServer(); err != nil {
		return nil, fmt.Errorf("cannot establish a connection: %w", err)
	}

	go h.Start()
	return h, nil
}

// Close releases the underlying connection. It is safe to call multiple times.
func (h *HepClient) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.client.conn == nil {
		return nil
	}

	err := h.client.conn.Close()
	h.client.conn = nil
	h.client.writer = nil

	if err != nil {
		return fmt.Errorf("cannot close connection to %s: %w", h.addr, err)
	}
	return nil
}

// ReConnect re-establishes the connection to the HEP server.
func (h *HepClient) ReConnect() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.reconnect()
}

func (h *HepClient) reconnect() error {
	if err := h.connectServer(); err != nil {
		return err
	}
	h.client.writer.Reset(h.client.conn)
	return nil
}

// ConnectServer establishes the connection to the HEP server.
func (h *HepClient) ConnectServer() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.connectServer()
}

func (h *HepClient) connectServer() error {
	var (
		conn net.Conn
		err  error
	)

	switch h.transport {
	case "udp":
		if conn, err = net.Dial("udp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	case "tcp":
		if conn, err = net.Dial("tcp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	case "tls":
		tlsConfig := h.tlsConfig
		if tlsConfig == nil {
			tlsConfig = defaultTLSConfig()
		}
		if conn, err = tls.Dial("tcp", h.addr, tlsConfig); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	default:
		return fmt.Errorf("unsupported transport: %s", h.transport)
	}

	// Only expose the connection once the dial has succeeded. Assigning the
	// result of tls.Dial directly would otherwise store a typed-nil *tls.Conn
	// inside the net.Conn interface even when the handshake fails.
	h.client.conn = conn
	h.client.writer = bufio.NewWriterSize(h.client.conn, 8192)
	return nil
}

// Output queues a HEP message for asynchronous delivery.
func (h *HepClient) Output(msg []byte) {
	h.hepQueue <- msg
	metrics.HEPQueueLength.Set(float64(len(h.hepQueue)))
}

// Send writes a single HEP message, transparently reconnecting (with backoff)
// when the write fails. It never terminates the process; callers decide how to
// handle a persistent failure.
func (h *HepClient) Send(msg []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	err := h.write(msg)
	if err == nil {
		h.client.errCnt = 0
		return nil
	}

	log.Printf("hep send error: %v; reconnecting to %s", err, h.addr)
	metrics.HEPSendErrors.Inc()
	return h.reconnectAndSend(msg, err)
}

func (h *HepClient) reconnectAndSend(msg []byte, cause error) error {
	if h.maxRetries <= 0 {
		h.client.errCnt++
		return cause
	}

	backoff := h.backoff
	lastErr := cause

	for attempt := 0; attempt < h.maxRetries; attempt++ {
		time.Sleep(backoff)

		backoff *= 2
		if backoff > h.maxBackoff {
			backoff = h.maxBackoff
		}

		if err := h.reconnect(); err != nil {
			lastErr = err
			continue
		}
		if err := h.write(msg); err != nil {
			lastErr = err
			continue
		}

		h.client.errCnt = 0
		metrics.HEPReconnects.Inc()
		return nil
	}

	h.client.errCnt++
	return fmt.Errorf("hep send failed after %d reconnect attempts: %w", h.maxRetries, lastErr)
}

func (h *HepClient) write(msg []byte) error {
	if h.client.writer == nil {
		return errors.New("hep client is not connected")
	}
	if _, err := h.client.writer.Write(msg); err != nil {
		return err
	}
	return h.client.writer.Flush()
}

// Start drains the outgoing queue until the process exits.
func (h *HepClient) Start() {
	for msg := range h.hepQueue {
		if err := h.Send(msg); err != nil {
			log.Printf("hep message dropped: %v", err)
		}
		metrics.HEPQueueLength.Set(float64(len(h.hepQueue)))
	}
}

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
