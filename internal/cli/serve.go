package cli

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/useless-husband/godig/internal/resolver"
	"github.com/useless-husband/godig/internal/server"
)

func runServe(ctx context.Context, args []string, env *Env) int {
	fs := flag.NewFlagSet("godig serve", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	port := fs.Int("port", 5353, "UDP and TCP port to listen on (0 = pick a free one)")
	addr := fs.String("addr", "127.0.0.1", "address to listen on")
	ipv6 := fs.Bool("ipv6", false, "allow IPv6 transport to upstream servers")
	quiet := fs.Bool("quiet", false, "do not log requests")
	no0x20 := fs.Bool("no-0x20", false, "disable 0x20 case randomization")
	cacheSize := fs.Int("cache-size", 10000, "maximum number of cached answers")
	timeout := fs.Duration("timeout", 2*time.Second, "timeout per upstream query")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: godig serve [--port N] [--addr A] [--ipv6] [--quiet] [--no-0x20] [--cache-size N] [--timeout D]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *port < 0 || *port > 65535 {
		fmt.Fprintln(env.Stderr, "godig: bad port")
		return ExitUsage
	}

	client := &resolver.Client{Timeout: *timeout, Retries: 1, Use0x20: !*no0x20}
	if env.ClientHook != nil {
		env.ClientHook(client)
	}
	zones := resolver.NewZoneCache(client.Now)
	res := &resolver.Resolver{Client: client, IPv6: *ipv6, Zones: zones}
	if env.ResolverHook != nil {
		env.ResolverHook(res)
	}
	cache := server.NewCache(env.Now)
	cache.MaxItems = *cacheSize
	cfg := server.Config{
		Addr:     net.JoinHostPort(*addr, strconv.Itoa(*port)),
		Resolver: res,
		Cache:    cache,
		Now:      env.Now,
	}
	if !*quiet {
		cfg.Logger = log.New(env.Stderr, "", log.LstdFlags)
	}
	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(env.Stderr, "godig: cannot listen on %s: %v\n", cfg.Addr, err)
		return ExitError
	}
	fmt.Fprintf(env.Stderr, "godig: serving on %s (udp+tcp); press Ctrl-C to stop\n", srv.Addr())
	if env.Ready != nil {
		env.Ready(srv.Addr())
	}
	<-ctx.Done()
	srv.Close()
	hits, misses := cache.Stats()
	fmt.Fprintf(env.Stderr, "godig: stopped. queries=%d cache_hits=%d cache_misses=%d upstream=%d coalesced=%d\n",
		srv.Queries.Load(), hits, misses, srv.Upstream.Load(), srv.Coalesced.Load())
	return ExitOK
}
