package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/resolver"
)

// Exit codes (the timeout code follows dig).
const (
	ExitOK      = 0
	ExitUsage   = 1
	ExitError   = 2
	ExitTimeout = 9
)

// Env carries everything Run needs from its surroundings, so tests can
// replace the clock, the random source and the root servers.
type Env struct {
	Stdout, Stderr io.Writer
	Version        string
	Now            func() time.Time
	ResolvConf     string // default /etc/resolv.conf

	// Test hooks.
	ClientHook   func(*resolver.Client)
	ResolverHook func(*resolver.Resolver)
	Ready        func(addr string) // serve: called once listening
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

const usage = `godig - a DNS resolver and lookup tool written from scratch

Usage:
  godig [@server] name [type] [options]     query a nameserver (like dig)
  godig +trace name [type]                  resolve iteratively from the root servers
  godig -x address                          reverse lookup (IPv4 or IPv6)
  godig serve [--port N] [--addr A]         run a small caching recursive resolver

Query options:
  -p port          server port (default 53)
  -t type          record type (A, AAAA, MX, TXT, NS, SOA, CNAME, PTR, SRV, CAA, ANY, TYPEnnn)
  +short           print only the record data
  +json            print the answer as JSON
  +tcp             use TCP instead of UDP
  +norec           clear the RD (recursion desired) flag
  +timeout=N       seconds to wait per attempt (default 3)
  +retry=N         extra attempts after the first (default 2)
  +trace           iterate from the root servers and print every step
  +ipv6            allow IPv6 transport for +trace
  +0x20 / +no0x20  force on/off 0x20 case randomization (default: on for +trace, off otherwise)
  +noedns          do not send an EDNS0 OPT record

Other:
  -h, --help       show this help
  -v, --version    show the version
`

// Run executes godig and returns the process exit code.
func Run(ctx context.Context, args []string, env *Env) int {
	if len(args) > 0 && args[0] == "serve" {
		return runServe(ctx, args[1:], env)
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stdout, usage)
		return ExitOK
	}
	opts, err := ParseArgs(args)
	if err != nil {
		fmt.Fprintf(env.Stderr, "godig: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if opts.Help || (opts.Name == "" && !opts.Version) {
		fmt.Fprint(env.Stdout, usage)
		return ExitOK
	}
	if opts.Version {
		fmt.Fprintf(env.Stdout, "godig %s\n", env.Version)
		return ExitOK
	}
	if opts.Trace {
		return runTrace(ctx, opts, env)
	}
	return runQuery(ctx, opts, env)
}

func newClient(opts *Options, env *Env, default0x20 bool) *resolver.Client {
	c := &resolver.Client{TCP: opts.TCP, NoEDNS: opts.NoEDNS, Use0x20: default0x20}
	if opts.Use0x20 {
		c.Use0x20 = true
	}
	if opts.No0x20 {
		c.Use0x20 = false
	}
	if opts.Timeout > 0 {
		c.Timeout = opts.Timeout
	}
	switch {
	case opts.Retry == 0:
		c.NoRetry = true
	case opts.Retry > 0:
		c.Retries = opts.Retry
	}
	if env.ClientHook != nil {
		env.ClientHook(c)
	}
	return c
}

func describe(opts *Options) string {
	s := dnsmsg.FQDN(opts.Name) + " " + opts.Type.String()
	if opts.Trace {
		s = "+trace " + s
	}
	return s
}

func runQuery(ctx context.Context, opts *Options, env *Env) int {
	client := newClient(opts, env, false)
	server := opts.Server
	if server == "" {
		conf := env.ResolvConf
		if conf == "" {
			conf = "/etc/resolv.conf"
		}
		server = DefaultServer(conf)
	}
	if _, err := netip.ParseAddr(server); err != nil {
		// A hostname: find its address with our own iterative resolver.
		ip, err := lookupHost(ctx, server, opts, env)
		if err != nil {
			fmt.Fprintf(env.Stderr, "godig: cannot resolve server name %q: %v\n", server, err)
			return ExitError
		}
		server = ip
	}
	addr := net.JoinHostPort(server, strconv.Itoa(opts.Port))
	resp, err := client.Exchange(ctx, addr, opts.Name, opts.Type, !opts.NoRec)
	if err != nil {
		fmt.Fprintf(env.Stderr, ";; communications error to %s: %v\n", addr, err)
		if errors.Is(err, resolver.ErrTimeout) {
			fmt.Fprintln(env.Stderr, ";; no servers could be reached")
			return ExitTimeout
		}
		return ExitError
	}
	switch {
	case opts.JSON:
		if err := WriteJSON(env.Stdout, resp); err != nil {
			fmt.Fprintf(env.Stderr, "godig: %v\n", err)
			return ExitError
		}
	case opts.Short:
		WriteShort(env.Stdout, resp.Msg)
	default:
		WriteDig(env.Stdout, describe(opts), resp, env.now())
	}
	return ExitOK
}

func newResolver(opts *Options, env *Env, client *resolver.Client) *resolver.Resolver {
	r := &resolver.Resolver{Client: client, IPv6: opts.IPv6}
	if env.ResolverHook != nil {
		env.ResolverHook(r)
	}
	return r
}

func lookupHost(ctx context.Context, host string, opts *Options, env *Env) (string, error) {
	c := newClient(opts, env, true)
	c.TCP = false
	r := newResolver(opts, env, c)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := r.Resolve(ctx, host, dnsmsg.TypeA)
	if err != nil {
		return "", err
	}
	for _, rr := range res.Answers {
		if a, ok := rr.Data.(dnsmsg.A); ok {
			return a.Addr.String(), nil
		}
	}
	return "", fmt.Errorf("no A record for %s", host)
}

func runTrace(ctx context.Context, opts *Options, env *Env) int {
	client := newClient(opts, env, true)
	if opts.Timeout == 0 {
		client.Timeout = 2 * time.Second
	}
	if opts.Retry < 0 {
		client.Retries = 1
	}
	r := newResolver(opts, env, client)
	roots := r.Roots
	if roots == nil {
		roots = resolver.RootServers
	}
	p := newTracePrinter(env.Stdout, roots)
	r.Trace = p.Event
	fmt.Fprintf(env.Stdout, "; <<>> godig <<>> %s\n", describe(opts))
	how := "IPv4"
	if opts.IPv6 {
		how = "IPv4 and IPv6"
	}
	fmt.Fprintf(env.Stdout, ";; starting from the built-in root hints (%d servers, %s), 0x20 case randomization %s\n\n",
		len(roots), how, map[bool]string{true: "on", false: "off"}[client.Use0x20])
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	res, err := r.Resolve(ctx, opts.Name, opts.Type)
	fmt.Fprintln(env.Stdout)
	if err != nil {
		fmt.Fprintf(env.Stderr, ";; trace failed: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(env.Stdout, ";; done: %s, %d answer records, %d queries sent\n", res.RCode, len(res.Answers), res.Queries)
	return ExitOK
}
