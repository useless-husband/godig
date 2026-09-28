package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/resolver"
)

// Resolver is what the server asks for answers. *resolver.Resolver satisfies it.
type Resolver interface {
	Resolve(ctx context.Context, name string, t dnsmsg.Type) (*resolver.Result, error)
}

// Config configures a Server.
type Config struct {
	Addr         string // host:port to listen on (UDP and TCP); port 0 picks a free one
	Resolver     Resolver
	Cache        *Cache
	Logger       *log.Logger // nil disables request logging
	Now          func() time.Time
	QueryTimeout time.Duration // upstream budget per question; default 10s
}

// Server is a caching recursive resolver speaking DNS over UDP and TCP.
type Server struct {
	cfg   Config
	group group
	pc    net.PacketConn
	ln    net.Listener
	wg    sync.WaitGroup
	sem   chan struct{}

	Queries   atomic.Int64
	CacheHits atomic.Int64
	Upstream  atomic.Int64 // resolutions actually started
	Coalesced atomic.Int64 // requests that shared another request's resolution
}

// New creates a server; call Start to begin listening.
func New(cfg Config) *Server {
	if cfg.Cache == nil {
		cfg.Cache = NewCache(cfg.Now)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 10 * time.Second
	}
	return &Server{cfg: cfg, sem: make(chan struct{}, 512)}
}

// Start binds UDP and TCP and serves in the background.
func (s *Server) Start() error {
	host, port, err := net.SplitHostPort(s.cfg.Addr)
	if err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		s.ln, err = net.Listen("tcp", s.cfg.Addr)
		if err != nil {
			return err
		}
		udpAddr := net.JoinHostPort(host, portOf(s.ln.Addr()))
		s.pc, err = net.ListenPacket("udp", udpAddr)
		if err == nil {
			break
		}
		s.ln.Close()
		if port != "0" {
			return err
		}
	}
	if err != nil {
		return err
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

func portOf(a net.Addr) string {
	_, p, _ := net.SplitHostPort(a.String())
	return p
}

// Addr returns the address the server listens on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops the listeners and waits for in-flight handlers.
func (s *Server) Close() {
	s.pc.Close()
	s.ln.Close()
	s.wg.Wait()
}

func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Printf(format, args...)
	}
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		select {
		case s.sem <- struct{}{}:
		default:
			continue // overloaded: drop, the client will retry
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			if out := s.HandlePacket(pkt, "udp", from.String()); out != nil {
				_, _ = s.pc.WriteTo(out, from)
			}
		}()
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
			for {
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				raw, err := resolver.ReadTCPMessage(c)
				if err != nil {
					if !errors.Is(err, io.EOF) {
						s.logf("tcp read from %s: %v", c.RemoteAddr(), err)
					}
					return
				}
				out := s.HandlePacket(raw, "tcp", c.RemoteAddr().String())
				if out == nil {
					return
				}
				if resolver.WriteTCPMessage(c, out) != nil {
					return
				}
			}
		}()
	}
}

// HandlePacket processes one wire-format query and returns the wire-format
// reply, or nil if the packet should be dropped.
func (s *Server) HandlePacket(pkt []byte, network, remote string) []byte {
	req, err := dnsmsg.Unpack(pkt)
	if err != nil {
		// Answer FORMERR when we at least have an ID to echo.
		if len(pkt) >= 12 && pkt[2]&0x80 == 0 {
			resp := &dnsmsg.Message{Header: dnsmsg.Header{ID: uint16(pkt[0])<<8 | uint16(pkt[1]), Response: true, RCode: dnsmsg.RCodeFormatError}}
			out, _ := resp.Pack()
			return out
		}
		return nil
	}
	if req.Response {
		return nil // never answer responses (avoids reflection loops)
	}
	start := s.cfg.Now()
	resp, source := s.Handle(req)
	limit := 65535
	if network == "udp" {
		limit = min(req.UDPSize(), dnsmsg.DefaultUDPSize)
	}
	out, err := resp.Pack()
	if err != nil || len(out) > limit {
		tr := &dnsmsg.Message{Header: resp.Header, Questions: resp.Questions}
		if err != nil {
			tr.RCode = dnsmsg.RCodeServerFailure
		} else {
			tr.Truncated = true
		}
		if _, ok := req.OPTRecord(); ok {
			tr.SetEDNS(dnsmsg.DefaultUDPSize, false)
		}
		out, _ = tr.Pack()
	}
	truncated := len(out) > 2 && out[2]&0x02 != 0
	q := "-"
	if len(req.Questions) > 0 {
		q = fmt.Sprintf("%s %s", req.Questions[0].Name, req.Questions[0].Type)
	}
	s.logf("client=%s proto=%s q=%q rcode=%s answers=%d source=%s tc=%v ms=%d",
		remote, network, q, resp.RCode, len(resp.Answers), source, truncated, s.cfg.Now().Sub(start).Milliseconds())
	return out
}

// Handle answers a parsed query. source describes where the data came from:
// "cache", "upstream", "coalesced" or "-" for errors that need no lookup.
func (s *Server) Handle(req *dnsmsg.Message) (*dnsmsg.Message, string) {
	s.Queries.Add(1)
	resp := &dnsmsg.Message{
		Header:    dnsmsg.Header{ID: req.ID, Response: true, Opcode: req.Opcode, RecursionDesired: req.RecursionDesired, RecursionAvailable: true},
		Questions: req.Questions,
	}
	if _, ok := req.OPTRecord(); ok {
		resp.SetEDNS(dnsmsg.DefaultUDPSize, false)
	}
	fail := func(rc dnsmsg.RCode) (*dnsmsg.Message, string) {
		resp.RCode = rc
		return resp, "-"
	}
	if req.Opcode != dnsmsg.OpcodeQuery {
		return fail(dnsmsg.RCodeNotImplemented)
	}
	if len(req.Questions) != 1 {
		return fail(dnsmsg.RCodeFormatError)
	}
	q := req.Questions[0]
	if q.Class != dnsmsg.ClassIN || q.Type == 251 || q.Type == 252 || q.Type == dnsmsg.TypeOPT {
		return fail(dnsmsg.RCodeRefused) // no zone transfers, no CHAOS
	}
	if res, ok := s.cfg.Cache.Get(q.Name, q.Type); ok {
		s.CacheHits.Add(1)
		return fill(resp, res), "cache"
	}
	key := dnsmsg.CanonicalName(q.Name) + "/" + strconv.Itoa(int(q.Type))
	res, err, shared := s.group.do(key, func() (*resolver.Result, error) {
		s.Upstream.Add(1)
		// Detached from any single client: the answer serves everyone waiting.
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout)
		defer cancel()
		r, err := s.cfg.Resolver.Resolve(ctx, q.Name, q.Type)
		if err == nil {
			s.cfg.Cache.Put(q.Name, q.Type, r)
		}
		return r, err
	})
	source := "upstream"
	if shared {
		s.Coalesced.Add(1)
		source = "coalesced"
	}
	if err != nil {
		resp.RCode = dnsmsg.RCodeServerFailure
		return resp, source
	}
	return fill(resp, res), source
}

func fill(resp *dnsmsg.Message, res *resolver.Result) *dnsmsg.Message {
	resp.RCode = res.RCode
	resp.Answers = append([]dnsmsg.RR(nil), res.Answers...)
	resp.Authorities = append([]dnsmsg.RR(nil), res.Authorities...)
	return resp
}
