package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/resolver"
)

// rrLine renders a record like dig: the owner name is padded with tabs to
// column 24.
func rrLine(rr dnsmsg.RR) string {
	return fmt.Sprintf("%s%d\t%s\t%s\t%s", pad(rr.Name), rr.TTL, rr.Class, rr.Type(), rr.Data)
}

func pad(name string) string {
	tabs := (24 - len(name) + 7) / 8
	if tabs < 1 {
		tabs = 1
	}
	return name + strings.Repeat("\t", tabs)
}

func flagString(h dnsmsg.Header) string {
	var f []string
	for _, p := range []struct {
		on   bool
		name string
	}{
		{h.Response, "qr"}, {h.Authoritative, "aa"}, {h.Truncated, "tc"}, {h.RecursionDesired, "rd"},
		{h.RecursionAvailable, "ra"}, {h.AuthenticData, "ad"}, {h.CheckingDisabled, "cd"},
	} {
		if p.on {
			f = append(f, p.name)
		}
	}
	return strings.Join(f, " ")
}

// serverLabel formats host:port the way dig prints SERVER.
func serverLabel(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return fmt.Sprintf("%s#%s(%s)", host, port, host)
}

func section(w io.Writer, title string, rrs []dnsmsg.RR) {
	n := 0
	for _, rr := range rrs {
		if rr.Type() != dnsmsg.TypeOPT {
			n++
		}
	}
	if n == 0 {
		return
	}
	fmt.Fprintf(w, ";; %s SECTION:\n", title)
	for _, rr := range rrs {
		if rr.Type() != dnsmsg.TypeOPT {
			fmt.Fprintln(w, rrLine(rr))
		}
	}
	fmt.Fprintln(w)
}

// WriteDig prints a full dig-style report.
func WriteDig(w io.Writer, cmd string, resp *resolver.Response, now time.Time) {
	m := resp.Msg
	if resp.FellBackToTCP {
		fmt.Fprintln(w, ";; Truncated, retrying in TCP mode.")
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "; <<>> godig <<>> %s\n", cmd)
	fmt.Fprintln(w, ";; Got answer:")
	fmt.Fprintf(w, ";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", m.Opcode, m.RCode, m.ID)
	fmt.Fprintf(w, ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
		flagString(m.Header), len(m.Questions), len(m.Answers), len(m.Authorities), len(m.Additionals))
	if opt, ok := m.OPTRecord(); ok {
		flags := ""
		if opt.TTL&0x8000 != 0 {
			flags = " do"
		}
		fmt.Fprintln(w, ";; OPT PSEUDOSECTION:")
		fmt.Fprintf(w, "; EDNS: version: %d, flags:%s; udp: %d\n", opt.TTL>>16&0xff, flags, uint16(opt.Class))
		fmt.Fprintln(w)
	}
	if len(m.Questions) > 0 {
		fmt.Fprintln(w, ";; QUESTION SECTION:")
		for _, q := range m.Questions {
			fmt.Fprintf(w, ";%s%s\t%s\n", pad(q.Name), q.Class, q.Type)
		}
		fmt.Fprintln(w)
	}
	section(w, "ANSWER", m.Answers)
	section(w, "AUTHORITY", m.Authorities)
	section(w, "ADDITIONAL", m.Additionals)
	fmt.Fprintf(w, ";; Query time: %d msec\n", resp.RTT.Milliseconds())
	fmt.Fprintf(w, ";; SERVER: %s (%s)\n", serverLabel(resp.Server), strings.ToUpper(resp.Network))
	fmt.Fprintf(w, ";; WHEN: %s\n", now.Format("Mon Jan _2 15:04:05 MST 2006"))
	fmt.Fprintf(w, ";; MSG SIZE  rcvd: %d\n", resp.Size)
}

// WriteShort prints only the record data, one per line.
func WriteShort(w io.Writer, m *dnsmsg.Message) {
	for _, rr := range m.Answers {
		fmt.Fprintln(w, rr.Data)
	}
}

type jsonRR struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type jsonQuestion struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type jsonEDNS struct {
	Version int    `json:"version"`
	UDPSize uint16 `json:"udp_size"`
	DO      bool   `json:"do"`
}

type jsonOutput struct {
	ID          uint16         `json:"id"`
	Opcode      string         `json:"opcode"`
	Status      string         `json:"status"`
	Flags       []string       `json:"flags"`
	Question    []jsonQuestion `json:"question"`
	Answer      []jsonRR       `json:"answer"`
	Authority   []jsonRR       `json:"authority"`
	Additional  []jsonRR       `json:"additional"`
	EDNS        *jsonEDNS      `json:"edns,omitempty"`
	Server      string         `json:"server"`
	Protocol    string         `json:"protocol"`
	QueryTimeMS int64          `json:"query_time_ms"`
	MsgSize     int            `json:"msg_size"`
}

func jsonRRs(rrs []dnsmsg.RR) []jsonRR {
	out := []jsonRR{}
	for _, rr := range rrs {
		if rr.Type() == dnsmsg.TypeOPT {
			continue
		}
		out = append(out, jsonRR{rr.Name, rr.Type().String(), rr.Class.String(), rr.TTL, rr.Data.String()})
	}
	return out
}

// WriteJSON prints the response as indented JSON.
func WriteJSON(w io.Writer, resp *resolver.Response) error {
	m := resp.Msg
	o := jsonOutput{
		ID: m.ID, Opcode: m.Opcode.String(), Status: m.RCode.String(),
		Flags:     strings.Fields(flagString(m.Header)),
		Question:  []jsonQuestion{},
		Answer:    jsonRRs(m.Answers),
		Authority: jsonRRs(m.Authorities), Additional: jsonRRs(m.Additionals),
		Server: resp.Server, Protocol: resp.Network, QueryTimeMS: resp.RTT.Milliseconds(), MsgSize: resp.Size,
	}
	for _, q := range m.Questions {
		o.Question = append(o.Question, jsonQuestion{q.Name, q.Type.String(), q.Class.String()})
	}
	if opt, ok := m.OPTRecord(); ok {
		o.EDNS = &jsonEDNS{Version: int(opt.TTL >> 16 & 0xff), UDPSize: uint16(opt.Class), DO: opt.TTL&0x8000 != 0}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}
