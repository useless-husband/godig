package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

func TestParseArgsBasic(t *testing.T) {
	o, err := ParseArgs([]string{"example.com", "MX", "@9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "example.com" || o.Type != dnsmsg.TypeMX || o.Server != "9.9.9.9" || o.Port != 53 || o.Retry != -1 {
		t.Fatalf("%+v", o)
	}
}

func TestParseArgsDefaultsToA(t *testing.T) {
	o, err := ParseArgs([]string{"example.com"})
	if err != nil || o.Type != dnsmsg.TypeA {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsOrderIndependent(t *testing.T) {
	o, err := ParseArgs([]string{"@1.1.1.1", "+short", "-p", "5353", "example.com", "txt", "IN"})
	if err != nil || o.Type != dnsmsg.TypeTXT || o.Port != 5353 || !o.Short || o.Server != "1.1.1.1" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsTypeFlagAndQuestionFlag(t *testing.T) {
	o, err := ParseArgs([]string{"-q", "example.com", "-t", "aaaa"})
	if err != nil || o.Name != "example.com" || o.Type != dnsmsg.TypeAAAA {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsReverseIPv4(t *testing.T) {
	o, err := ParseArgs([]string{"-x", "8.8.4.4"})
	if err != nil || o.Name != "4.4.8.8.in-addr.arpa." || o.Type != dnsmsg.TypePTR {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsReverseIPv6(t *testing.T) {
	o, err := ParseArgs([]string{"-x", "::1"})
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
	if err != nil || o.Name != want || o.Type != dnsmsg.TypePTR {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsPlusOptions(t *testing.T) {
	o, err := ParseArgs([]string{"example.com", "+json", "+tcp", "+norec", "+trace", "+timeout=5", "+retry=3", "+0x20", "+ipv6", "+noedns"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.JSON || !o.TCP || !o.NoRec || !o.Trace || !o.Use0x20 || !o.IPv6 || !o.NoEDNS || o.Timeout != 5*time.Second || o.Retry != 3 {
		t.Fatalf("%+v", o)
	}
	o, _ = ParseArgs([]string{"example.com", "+tries=1"})
	if o.Retry != 0 {
		t.Fatalf("+tries=1 means no retries, got %d", o.Retry)
	}
	o, _ = ParseArgs([]string{"example.com", "+tcp", "+notcp", "+norec", "+recurse"})
	if o.TCP || o.NoRec {
		t.Fatalf("%+v", o)
	}
}

func TestParseArgsErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"example.com", "+timeout=abc"},
		{"example.com", "+timeout"},
		{"example.com", "+retry=-1"},
		{"example.com", "+wat"},
		{"example.com", "BOGUSTYPE"},
		{"example.com", "-p", "0"},
		{"example.com", "-p"},
		{"example.com", "-z"},
		{"-x", "not-an-ip"},
		{"example.com", "@"},
		{"a..b"},
	} {
		if _, err := ParseArgs(args); err == nil {
			t.Errorf("%v should fail", args)
		}
	}
}

func TestDefaultServerReadsResolvConf(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "resolv.conf")
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := DefaultServer(write("# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver 8.8.8.8\n")); got != "192.168.1.1" {
		t.Fatal(got)
	}
	if got := DefaultServer(write("nameserver fe80::1%en0\n")); got != "fe80::1%en0" {
		t.Fatal(got)
	}
	if got := DefaultServer(write("# nothing useful\n")); got != "1.1.1.1" {
		t.Fatal(got)
	}
	if got := DefaultServer(write("nameserver not-an-ip\n")); got != "1.1.1.1" {
		t.Fatal(got)
	}
	if got := DefaultServer(filepath.Join(dir, "missing")); got != "1.1.1.1" {
		t.Fatal(got)
	}
}

func TestPadAlignsToColumn24(t *testing.T) {
	cases := map[string]string{"a.": "a.\t\t\t", "example.com.": "example.com.\t\t", "averyveryverylongname.example.": "averyveryverylongname.example.\t"}
	for in, want := range cases {
		if got := pad(in); got != want {
			t.Errorf("pad(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseArgsTypeBeforeName(t *testing.T) {
	o, err := ParseArgs([]string{"mx", "example.com"})
	if err != nil || o.Name != "example.com" || o.Type != dnsmsg.TypeMX {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = ParseArgs([]string{"a"}) // a lone word is always the name
	if err != nil || o.Name != "a" || o.Type != dnsmsg.TypeA {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestParseArgsUnknownSecondWordIsTypeError(t *testing.T) {
	if _, err := ParseArgs([]string{"example.com", "example.org"}); err == nil {
		t.Fatal("two names should be rejected")
	}
}
