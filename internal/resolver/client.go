// Package resolver contains the DNS client (UDP with TCP fallback) and the
// iterative resolver that walks the delegation chain from the root servers.
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

// Errors returned by Client.Exchange.
var (
	ErrTimeout  = errors.New("resolver: timed out waiting for a valid reply")
	ErrMismatch = errors.New("resolver: reply does not match the query")
	ErrCase0x20 = errors.New("resolver: server did not preserve query name case (0x20)")
)

// Client sends single queries to a single server.
type Client struct {
	Timeout time.Duration // per attempt; default 3s
	Retries int           // extra UDP attempts after the first; default 2 (set NoRetry for 0)
	NoRetry bool
	TCP     bool // use TCP only
	Use0x20 bool // randomize the case of the query name and require it echoed back
	NoEDNS  bool
	UDPSize uint16 // advertised EDNS size; default 1232

	// Hooks for tests. All optional.
	Now  func() time.Time // used for RTT measurement only
	Rand io.Reader        // source for message IDs and 0x20 bits; default crypto/rand
}

// Response is a validated reply together with transport details.
type Response struct {
	Msg           *dnsmsg.Message
	Size          int
	RTT           time.Duration
	Server        string
	Network       string // "udp" or "tcp"
	FellBackToTCP bool
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 3 * time.Second
}

func (c *Client) attempts() int {
	if c.NoRetry {
		return 1
	}
	if c.Retries > 0 {
		return c.Retries + 1
	}
	return 3
}

func (c *Client) randBytes(n int) []byte {
	b := make([]byte, n)
	r := c.Rand
	if r == nil {
		r = rand.Reader
	}
	if _, err := io.ReadFull(r, b); err != nil {
		panic("resolver: random source failed: " + err.Error())
	}
	return b
}

// Randomize0x20 flips the case of ASCII letters at random (the "0x20" bit),
// making the name an extra unpredictable value an off-path attacker has to
// guess in order to forge an answer.
func Randomize0x20(name string, r io.Reader) string {
	letters := 0
	for i := 0; i < len(name); i++ {
		if isLetter(name[i]) {
			letters++
		}
	}
	bits := make([]byte, (letters+7)/8)
	if _, err := io.ReadFull(r, bits); err != nil {
		return name
	}
	out := []byte(name)
	k := 0
	for i, ch := range out {
		if !isLetter(ch) {
			continue
		}
		if bits[k/8]>>(k%8)&1 == 1 {
			out[i] = ch &^ 0x20 // upper case
		} else {
			out[i] = ch | 0x20 // lower case
		}
		k++
	}
	return string(out)
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

func (c *Client) buildQuery(name string, t dnsmsg.Type, rd, use0x20 bool) (*dnsmsg.Message, []byte, error) {
	id := binary.BigEndian.Uint16(c.randBytes(2))
	qname := dnsmsg.FQDN(name)
	if use0x20 {
		r := c.Rand
		if r == nil {
			r = rand.Reader
		}
		qname = Randomize0x20(qname, r)
	}
	q := dnsmsg.NewQuery(id, qname, t, rd, !c.NoEDNS)
	if !c.NoEDNS && c.UDPSize != 0 {
		q.SetEDNS(c.UDPSize, false)
	}
	wire, err := q.Pack()
	return q, wire, err
}

// Exchange asks server (host:port) for name/type. UDP is used unless c.TCP is
// set; a truncated UDP reply is retried over TCP.
func (c *Client) Exchange(ctx context.Context, server, name string, t dnsmsg.Type, rd bool) (*Response, error) {
	if c.TCP {
		return c.exchangeTCP(ctx, server, name, t, rd)
	}
	var lastErr error
	use0x20 := c.Use0x20
	for i := 0; i < c.attempts(); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := c.exchangeUDP(ctx, server, name, t, rd, use0x20)
		if err == nil {
			if resp.Msg.Truncated {
				tcp, terr := c.exchangeTCP(ctx, server, name, t, rd)
				if terr != nil {
					return nil, fmt.Errorf("truncated UDP reply, TCP retry failed: %w", terr)
				}
				tcp.FellBackToTCP = true
				return tcp, nil
			}
			return resp, nil
		}
		lastErr = err
		if errors.Is(err, ErrCase0x20) {
			use0x20 = false // this server lowercases names; retry without 0x20
			continue
		}
		if !errors.Is(err, ErrTimeout) {
			return nil, err
		}
	}
	return nil, lastErr
}

// matches reports whether msg is an acceptable reply to the query q.
// strict requires an exact (case-sensitive) echo of the question name.
func matches(q, msg *dnsmsg.Message, strict bool) (ok, caseOnly bool) {
	if msg.ID != q.ID || !msg.Response || len(msg.Questions) != 1 {
		return false, false
	}
	a, b := q.Questions[0], msg.Questions[0]
	if a.Type != b.Type || a.Class != b.Class || !dnsmsg.EqualNames(a.Name, b.Name) {
		return false, false
	}
	if strict && a.Name != b.Name {
		return false, true
	}
	return true, false
}

func (c *Client) exchangeUDP(ctx context.Context, server, name string, t dnsmsg.Type, rd, use0x20 bool) (*Response, error) {
	q, wire, err := c.buildQuery(name, t, rd, use0x20)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(c.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	start := c.now()
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	sawCase := false
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if sawCase {
					return nil, ErrCase0x20
				}
				return nil, fmt.Errorf("%w (%s)", ErrTimeout, server)
			}
			return nil, err
		}
		raw := buf[:n]
		msg, perr := dnsmsg.Unpack(raw)
		if perr != nil {
			// A truncated reply may be cut in the middle of a record.
			if len(raw) < 4 || raw[2]&0x02 == 0 {
				continue
			}
			if msg, perr = dnsmsg.UnpackTruncated(raw); perr != nil {
				continue
			}
		}
		ok, caseOnly := matches(q, msg, use0x20)
		if caseOnly {
			sawCase = true
		}
		if !ok {
			continue // unrelated or forged packet: keep waiting
		}
		return &Response{Msg: msg, Size: n, RTT: c.now().Sub(start), Server: server, Network: "udp"}, nil
	}
}

func (c *Client) exchangeTCP(ctx context.Context, server, name string, t dnsmsg.Type, rd bool) (*Response, error) {
	q, wire, err := c.buildQuery(name, t, rd, c.Use0x20)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	dctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(c.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	start := c.now()
	if err := WriteTCPMessage(conn, wire); err != nil {
		return nil, err
	}
	raw, err := ReadTCPMessage(conn)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("%w (%s, tcp)", ErrTimeout, server)
		}
		return nil, err
	}
	msg, err := dnsmsg.Unpack(raw)
	if err != nil {
		return nil, fmt.Errorf("bad reply from %s: %w", server, err)
	}
	ok, caseOnly := matches(q, msg, c.Use0x20)
	if !ok {
		if caseOnly {
			return nil, ErrCase0x20
		}
		return nil, ErrMismatch
	}
	return &Response{Msg: msg, Size: len(raw), RTT: c.now().Sub(start), Server: server, Network: "tcp"}, nil
}

// WriteTCPMessage sends a message with the 2-byte big-endian length prefix
// that DNS over TCP requires (RFC 1035 section 4.2.2).
func WriteTCPMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xffff {
		return dnsmsg.ErrTooLarge
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

// ReadTCPMessage reads one length-prefixed message.
func ReadTCPMessage(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
