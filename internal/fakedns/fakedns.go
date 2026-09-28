// Package fakedns provides in-process fake DNS servers for tests. Every
// server listens on 127.0.0.1 with an OS-assigned port, over both UDP and
// TCP, so tests never touch the network.
package fakedns

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

// Handler builds a reply for a query; returning nil means "stay silent".
type Handler func(req *dnsmsg.Message, network string) *dnsmsg.Message

// Server is a running fake server.
type Server struct {
	Addr string // 127.0.0.1:port, same port for UDP and TCP

	udp, tcp atomic.Int64
	pc       net.PacketConn
	ln       net.Listener
	h        Handler
	mangle   func(req *dnsmsg.Message, reply []byte) [][]byte
	noTrunc  bool
	wg       sync.WaitGroup
}

// Option customizes a fake server.
type Option func(*Server)

// WithMangle lets a test replace the UDP datagrams sent for a reply, e.g. to
// send a forged packet first.
func WithMangle(f func(req *dnsmsg.Message, reply []byte) [][]byte) Option {
	return func(s *Server) { s.mangle = f }
}

// WithoutTruncation disables the automatic TC handling on UDP.
func WithoutTruncation() Option { return func(s *Server) { s.noTrunc = true } }

// UDPQueries and TCPQueries count queries received so far.
func (s *Server) UDPQueries() int { return int(s.udp.Load()) }
func (s *Server) TCPQueries() int { return int(s.tcp.Load()) }

// Queries counts both.
func (s *Server) Queries() int { return s.UDPQueries() + s.TCPQueries() }

// Port returns the numeric port.
func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(s.Addr)
	n, _ := strconv.Atoi(p)
	return n
}

// Start launches a server and stops it when the test ends.
func Start(t testing.TB, h Handler, opts ...Option) *Server {
	t.Helper()
	s := &Server{h: h}
	for _, o := range opts {
		o(s)
	}
	var err error
	for i := 0; i < 50; i++ {
		s.ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s.pc, err = net.ListenPacket("udp", s.ln.Addr().String())
		if err == nil {
			break
		}
		s.ln.Close() // UDP port taken by someone else: try another
	}
	if err != nil {
		t.Fatalf("fakedns: cannot bind matching UDP/TCP ports: %v", err)
	}
	s.Addr = s.ln.Addr().String()
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	t.Cleanup(s.Close)
	return s
}

// Close stops the server.
func (s *Server) Close() {
	s.pc.Close()
	s.ln.Close()
	s.wg.Wait()
}

func (s *Server) reply(req *dnsmsg.Message, network string) *dnsmsg.Message {
	resp := s.h(req, network)
	if resp == nil {
		return nil
	}
	resp.ID = req.ID
	resp.Response = true
	if len(resp.Questions) == 0 {
		resp.Questions = req.Questions // echo with the client's letter case
	}
	return resp
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dnsmsg.Unpack(buf[:n])
		if err != nil {
			continue
		}
		s.udp.Add(1)
		resp := s.reply(req, "udp")
		if resp == nil {
			continue
		}
		wire, err := resp.Pack()
		if err != nil {
			continue
		}
		if !s.noTrunc && len(wire) > req.UDPSize() {
			tr := &dnsmsg.Message{Header: resp.Header, Questions: resp.Questions}
			tr.Truncated = true
			wire, _ = tr.Pack()
		}
		out := [][]byte{wire}
		if s.mangle != nil {
			out = s.mangle(req, wire)
		}
		for _, p := range out {
			_, _ = s.pc.WriteTo(p, from)
		}
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			for {
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				raw := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, raw); err != nil {
					return
				}
				req, err := dnsmsg.Unpack(raw)
				if err != nil {
					return
				}
				s.tcp.Add(1)
				resp := s.reply(req, "tcp")
				if resp == nil {
					return
				}
				wire, err := resp.Pack()
				if err != nil {
					return
				}
				out := make([]byte, 2+len(wire))
				binary.BigEndian.PutUint16(out, uint16(len(wire)))
				copy(out[2:], wire)
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}()
	}
}
