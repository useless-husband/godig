// Package cli implements the godig command line: dig-style queries, +trace
// and the "serve" subcommand.
package cli

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

// Options is the parsed form of a query command line.
type Options struct {
	Name   string
	Type   dnsmsg.Type
	Server string // host or IP from @server; empty = system default
	Port   int

	Short   bool
	JSON    bool
	TCP     bool
	NoRec   bool
	Trace   bool
	Use0x20 bool
	No0x20  bool
	IPv6    bool
	NoEDNS  bool
	Timeout time.Duration
	Retry   int // extra attempts; -1 = default

	Help    bool
	Version bool
}

// ParseArgs turns dig-like arguments into Options.
//
//	godig [@server] [name] [type] [-x addr] [-p port] [-t type] [+options]
func ParseArgs(args []string) (*Options, error) {
	o := &Options{Port: 53, Retry: -1, Type: dnsmsg.TypeA}
	typeSet := false
	setType := func(s string) error {
		t, ok := dnsmsg.ParseType(s)
		if !ok {
			return fmt.Errorf("unknown record type %q", s)
		}
		o.Type, typeSet = t, true
		return nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		need := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("option %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		switch {
		case a == "-h" || a == "--help" || a == "help":
			o.Help = true
		case a == "-v" || a == "--version" || a == "version":
			o.Version = true
		case a == "-x":
			v, err := need()
			if err != nil {
				return nil, err
			}
			ip, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("-x needs an IP address, got %q", v)
			}
			o.Name = dnsmsg.ReverseName(ip)
			if !typeSet {
				o.Type = dnsmsg.TypePTR
			}
		case a == "-p":
			v, err := need()
			if err != nil {
				return nil, err
			}
			p, err := strconv.Atoi(v)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("bad port %q", v)
			}
			o.Port = p
		case a == "-t":
			v, err := need()
			if err != nil {
				return nil, err
			}
			if err := setType(v); err != nil {
				return nil, err
			}
		case a == "-q":
			v, err := need()
			if err != nil {
				return nil, err
			}
			o.Name = v
		case strings.HasPrefix(a, "@"):
			o.Server = strings.Trim(a[1:], "[]")
			if o.Server == "" {
				return nil, fmt.Errorf("empty server after @")
			}
		case strings.HasPrefix(a, "+"):
			if err := o.parsePlus(a[1:]); err != nil {
				return nil, err
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			return nil, fmt.Errorf("unknown option %q", a)
		default:
			if o.Name == "" {
				o.Name = a
			} else if strings.EqualFold(a, "IN") {
				// class IN is the only class we speak
			} else if err := setType(a); err != nil {
				return nil, err
			}
		}
	}
	if o.Name == "" && !o.Help && !o.Version {
		return nil, fmt.Errorf("no query name given")
	}
	if o.Name != "" {
		if err := dnsmsg.ValidName(o.Name); err != nil {
			return nil, fmt.Errorf("bad name %q: %v", o.Name, err)
		}
	}
	return o, nil
}

func (o *Options) parsePlus(s string) error {
	key, val, hasVal := strings.Cut(s, "=")
	num := func() (int, error) {
		if !hasVal {
			return 0, fmt.Errorf("+%s needs a value (+%s=N)", key, key)
		}
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad value for +%s: %q", key, val)
		}
		return n, nil
	}
	switch key {
	case "short":
		o.Short = true
	case "json":
		o.JSON = true
	case "tcp":
		o.TCP = true
	case "notcp":
		o.TCP = false
	case "norec", "norecurse":
		o.NoRec = true
	case "rec", "recurse":
		o.NoRec = false
	case "trace":
		o.Trace = true
	case "0x20":
		o.Use0x20 = true
	case "no0x20":
		o.No0x20 = true
	case "ipv6":
		o.IPv6 = true
	case "noedns":
		o.NoEDNS = true
	case "timeout", "time":
		n, err := num()
		if err != nil {
			return err
		}
		if n == 0 {
			n = 1
		}
		o.Timeout = time.Duration(n) * time.Second
	case "retry":
		n, err := num()
		if err != nil {
			return err
		}
		o.Retry = n
	case "tries":
		n, err := num()
		if err != nil {
			return err
		}
		o.Retry = max(n-1, 0)
	default:
		return fmt.Errorf("unknown option +%s", s)
	}
	return nil
}

// DefaultServer returns the first nameserver from a resolv.conf-style file,
// or 1.1.1.1 if there is none.
func DefaultServer(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "1.1.1.1"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if _, err := netip.ParseAddr(strings.SplitN(fields[1], "%", 2)[0]); err == nil {
				return fields[1]
			}
		}
	}
	return "1.1.1.1"
}
