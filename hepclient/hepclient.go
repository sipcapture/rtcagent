package hepclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"unicode"
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
	client    HEPConn
}

func NewHepClient(addr, port, trans string) (*HepClient, error) {

	h := &HepClient{
		addr:      strings.ToLower(cutSpace(addr + ":" + port)),
		client:    HEPConn{},
		transport: trans,
		hepQueue:  make(chan []byte, 20000),
	}

	if err := h.ConnectServer(); err != nil {
		log.Fatalf("Error: %s", err.Error())
		return nil, fmt.Errorf("cannot establish a connection")
	}

	go h.Start()
	return h, nil
}

func (h *HepClient) Close() {
	if err := h.client.conn.Close(); err != nil {
		log.Fatalf("cannnot close connection to %s: %v", h.addr, err)
	}
}

func (h *HepClient) ReConnect() (err error) {
	if err = h.ConnectServer(); err != nil {
		return err
	}
	h.client.writer.Reset(h.client.conn)
	return err
}

func (h *HepClient) ConnectServer() (err error) {
	if h.transport == "udp" {

		if h.client.conn, err = net.Dial("udp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else if h.transport == "tcp" {

		if h.client.conn, err = net.Dial("tcp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else if h.transport == "tls" {
		if h.client.conn, err = tls.Dial("tcp", h.addr, &tls.Config{InsecureSkipVerify: true}); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else {
		return fmt.Errorf("unsupported transport: %s", h.transport)
	}

	h.client.writer = bufio.NewWriterSize(h.client.conn, 8192)
	return err
}

func (h *HepClient) Output(msg []byte) {
	h.hepQueue <- msg
}

func (h *HepClient) Send(msg []byte) {
	h.client.writer.Write(msg)
	err := h.client.writer.Flush()
	if err != nil {
		log.Fatal("%v", err)
		h.client.errCnt++
		retry := true
		if retry {
			h.client.errCnt = 0
			if err = h.ReConnect(); err != nil {
				log.Fatalf("reconnect error: %v", err)
				return
			}
		}
	}
}

func (h *HepClient) Start() {
	for msg := range h.hepQueue {
		h.Send(msg)
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
