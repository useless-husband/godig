package dnsmsg

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func roundTrip(t *testing.T, data RData) RR {
	t.Helper()
	m := &Message{
		Header:    Header{ID: 0xbeef, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []Question{{"example.com.", data.Type(), ClassIN}},
		Answers:   []RR{{Name: "example.com.", Class: ClassIN, TTL: 300, Data: data}},
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(got.Answers) != 1 {
		t.Fatalf("want 1 answer, got %d", len(got.Answers))
	}
	if !reflect.DeepEqual(got.Answers[0], m.Answers[0]) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got.Answers[0], m.Answers[0])
	}
	return got.Answers[0]
}

func TestRoundTripA(t *testing.T) {
	rr := roundTrip(t, A{netip.MustParseAddr("93.184.216.34")})
	if rr.String() != "example.com.\t300\tIN\tA\t93.184.216.34" {
		t.Fatal(rr.String())
	}
}

func TestRoundTripAAAA(t *testing.T) {
	roundTrip(t, AAAA{netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")})
}

func TestRoundTripCNAME(t *testing.T) { roundTrip(t, CNAME{"www.example.net."}) }
func TestRoundTripNS(t *testing.T)    { roundTrip(t, NS{"ns1.example.com."}) }
func TestRoundTripPTR(t *testing.T)   { roundTrip(t, PTR{"host.example.org."}) }

func TestRoundTripMX(t *testing.T) {
	rr := roundTrip(t, MX{10, "mail.example.com."})
	if !strings.HasSuffix(rr.String(), "MX\t10 mail.example.com.") {
		t.Fatal(rr.String())
	}
}

func TestRoundTripTXTMultiString(t *testing.T) {
	rr := roundTrip(t, TXT{[]string{"v=spf1 include:_spf.example.com", "~all", ""}})
	if rr.Data.String() != `"v=spf1 include:_spf.example.com" "~all" ""` {
		t.Fatal(rr.Data.String())
	}
}

func TestTXTLongStringRejected(t *testing.T) {
	m := &Message{Answers: []RR{{Name: "a.", Class: ClassIN, Data: TXT{[]string{strings.Repeat("x", 256)}}}}}
	if _, err := m.Pack(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestTXTQuoting(t *testing.T) {
	got := TXT{[]string{"a\"b\\c\x01"}}.String()
	if got != `"a\"b\\c\001"` {
		t.Fatal(got)
	}
}

func TestRoundTripSOA(t *testing.T) {
	rr := roundTrip(t, SOA{"ns.example.com.", "admin.example.com.", 2026092901, 7200, 3600, 1209600, 300})
	if rr.Data.String() != "ns.example.com. admin.example.com. 2026092901 7200 3600 1209600 300" {
		t.Fatal(rr.Data.String())
	}
}

func TestRoundTripSRV(t *testing.T) {
	rr := roundTrip(t, SRV{10, 60, 5060, "sip.example.com."})
	if rr.Data.String() != "10 60 5060 sip.example.com." {
		t.Fatal(rr.Data.String())
	}
}

func TestRoundTripCAA(t *testing.T) {
	rr := roundTrip(t, CAA{128, "issue", "letsencrypt.org"})
	if rr.Data.String() != `128 issue "letsencrypt.org"` {
		t.Fatal(rr.Data.String())
	}
}

func TestRoundTripUnknownType(t *testing.T) {
	rr := roundTrip(t, Unknown{T: 65, Data: []byte{0xde, 0xad, 0xbe, 0xef}})
	if rr.Data.String() != `\# 4 deadbeef` {
		t.Fatal(rr.Data.String())
	}
	if rr.Type().String() != "TYPE65" {
		t.Fatal(rr.Type())
	}
}

func TestUnknownEmptyData(t *testing.T) {
	rr := roundTrip(t, Unknown{T: 999})
	if rr.Data.String() != `\# 0` {
		t.Fatal(rr.Data.String())
	}
}

func TestParseUnknown(t *testing.T) {
	u, err := ParseUnknown(65, `\# 4 dead beef`)
	if err != nil || !bytes.Equal(u.Data, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatal(u, err)
	}
	for _, bad := range []string{`\# 3 dead`, `4 deadbeef`, `\# x`, `\# 2 zz`} {
		if _, err := ParseUnknown(65, bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestRoundTripOPTWithOptions(t *testing.T) {
	m := NewQuery(1, "example.com", TypeA, true, true)
	m.Additionals[0].Data = OPT{Options: []EDNSOption{{10, []byte{1, 2, 3, 4, 5, 6, 7, 8}}, {3, nil}}}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	rr, ok := got.OPTRecord()
	if !ok || rr.Class != DefaultUDPSize {
		t.Fatalf("OPT = %+v %v", rr, ok)
	}
	if o := rr.Data.(OPT); len(o.Options) != 2 || o.Options[0].Code != 10 || len(o.Options[1].Data) != 0 {
		t.Fatalf("options = %+v", o)
	}
}

func TestEDNSDefaultsAndReplace(t *testing.T) {
	m := NewQuery(7, "example.com", TypeA, true, true)
	if m.UDPSize() != 1232 {
		t.Fatalf("udp size %d", m.UDPSize())
	}
	m.SetEDNS(4096, true)
	if len(m.Additionals) != 1 || m.UDPSize() != 4096 || m.Additionals[0].TTL != 0x8000 {
		t.Fatalf("%+v", m.Additionals)
	}
	if NewQuery(1, "a.", TypeA, false, false).UDPSize() != 512 {
		t.Fatal("no EDNS should mean 512")
	}
}

func TestHeaderFlagsRoundTrip(t *testing.T) {
	h := Header{ID: 0x1234, Response: true, Opcode: OpcodeStatus, Authoritative: true, Truncated: true,
		RecursionDesired: true, RecursionAvailable: true, AuthenticData: true, CheckingDisabled: true, RCode: RCodeRefused}
	m := &Message{Header: h}
	wire, _ := m.Pack()
	got, err := Unpack(wire)
	if err != nil || got.Header != h {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestHeaderBytes(t *testing.T) {
	m := &Message{Header: Header{ID: 0xabcd, RecursionDesired: true}}
	wire, _ := m.Pack()
	if hex.EncodeToString(wire) != "abcd01000000000000000000" {
		t.Fatal(hex.EncodeToString(wire))
	}
}

func TestQueryWireFormat(t *testing.T) {
	wire, err := NewQuery(0x1234, "example.com", TypeA, true, false).Pack()
	if err != nil {
		t.Fatal(err)
	}
	want := "123401000001000000000000" + "076578616d706c6503636f6d00" + "00010001"
	if hex.EncodeToString(wire) != want {
		t.Fatalf("got %x", wire)
	}
}

func TestNameCompressionOnEncode(t *testing.T) {
	m := &Message{
		Questions: []Question{{"www.example.com.", TypeA, ClassIN}},
		Answers: []RR{
			{Name: "www.example.com.", Class: ClassIN, TTL: 1, Data: CNAME{"web.example.com."}},
			{Name: "WEB.Example.COM.", Class: ClassIN, TTL: 1, Data: A{netip.MustParseAddr("192.0.2.1")}},
		},
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	// Question name starts at 12; the answer owner must be a pointer to it.
	if !bytes.Contains(wire, []byte{0xC0, 0x0C}) {
		t.Fatalf("expected pointer to offset 12 in %x", wire)
	}
	if bytes.Count(wire, []byte("example")) != 1 {
		t.Fatalf("suffix written more than once: %x", wire)
	}
	got, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Answers[0].Data.(CNAME).Target != "web.example.com." {
		t.Fatalf("%+v", got.Answers[0])
	}
	if !EqualNames(got.Answers[1].Name, "web.example.com.") {
		t.Fatal(got.Answers[1].Name)
	}
}

func TestSRVTargetNotCompressed(t *testing.T) {
	m := &Message{
		Questions: []Question{{"sip.example.com.", TypeSRV, ClassIN}},
		Answers:   []RR{{Name: "sip.example.com.", Class: ClassIN, Data: SRV{1, 2, 3, "sip.example.com."}}},
	}
	wire, _ := m.Pack()
	if bytes.Count(wire, []byte("example")) != 2 {
		t.Fatalf("SRV target should be written in full: %x", wire)
	}
}

func TestDecodeCompressedNameManual(t *testing.T) {
	// header + question example.com A, answer name = pointer(12)
	h := "beef81800001000100000000"
	q := "076578616d706c6503636f6d0000010001"
	a := "c00c" + "0001" + "0001" + "0000003c" + "0004" + "5db8d822"
	wire, _ := hex.DecodeString(h + q + a)
	m, err := Unpack(wire)
	if err != nil {
		t.Fatal(err)
	}
	if m.Answers[0].Name != "example.com." || m.Answers[0].Data.String() != "93.184.216.34" || m.Answers[0].TTL != 60 {
		t.Fatalf("%+v", m.Answers[0])
	}
	if !m.Response || !m.RecursionAvailable {
		t.Fatal("flags")
	}
}

func hdr(qd, an int) []byte {
	return []byte{0, 1, 0, 0, byte(qd >> 8), byte(qd), byte(an >> 8), byte(an), 0, 0, 0, 0}
}

func TestMaliciousPointerLoop(t *testing.T) {
	// name at 12: label "a" then pointer back to 12 -> infinite expansion
	b := append(hdr(1, 0), 1, 'a', 0xC0, 12, 0, 1, 0, 1)
	if _, err := Unpack(b); !errors.Is(err, ErrPointerLoop) {
		t.Fatalf("want ErrPointerLoop, got %v", err)
	}
}

func TestMaliciousSelfPointer(t *testing.T) {
	b := append(hdr(1, 0), 0xC0, 12, 0, 1, 0, 1)
	if _, err := Unpack(b); !errors.Is(err, ErrBadPointer) {
		t.Fatalf("want ErrBadPointer, got %v", err)
	}
}

func TestMaliciousForwardPointer(t *testing.T) {
	b := append(hdr(1, 0), 0xC0, 20, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0)
	if _, err := Unpack(b); !errors.Is(err, ErrBadPointer) {
		t.Fatalf("want ErrBadPointer, got %v", err)
	}
}

func TestMaliciousPointerBeyondMessage(t *testing.T) {
	b := append(hdr(1, 0), 0xC0, 0xFF, 0, 1, 0, 1)
	if _, err := Unpack(b); !errors.Is(err, ErrBadPointer) {
		t.Fatalf("got %v", err)
	}
}

func TestMaliciousPointerChainDepth(t *testing.T) {
	// 30 pointers, each pointing at the previous one: bounded by maxJumps.
	msg := append(hdr(1, 0), 0) // offset 12: root label
	prev := 12
	for i := 0; i < 30; i++ {
		msg = append(msg, 0xC0, byte(prev))
		prev = len(msg) - 2
	}
	if _, _, err := readName(msg, prev); !errors.Is(err, ErrPointerLoop) {
		t.Fatalf("want ErrPointerLoop, got %v", err)
	}
}

func TestMaliciousLabelTooLong(t *testing.T) {
	b := hdr(1, 0)
	b = append(b, 64)
	b = append(b, bytes.Repeat([]byte{'a'}, 64)...)
	b = append(b, 0, 0, 1, 0, 1)
	if _, err := Unpack(b); !errors.Is(err, ErrBadLabel) {
		// 64 = 0x40 is a reserved label type, so it must be refused as such.
		t.Fatalf("got %v", err)
	}
}

func TestMaliciousNameTooLong(t *testing.T) {
	b := hdr(1, 0)
	for i := 0; i < 5; i++ { // 5 * 61 = 305 > 255
		b = append(b, 60)
		b = append(b, bytes.Repeat([]byte{'a'}, 60)...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	if _, err := Unpack(b); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("got %v", err)
	}
}

func TestNameExactly255Accepted(t *testing.T) {
	// 3*(1+63) + 1+61 + 1 = 255 bytes on the wire.
	var b []byte
	for i := 0; i < 3; i++ {
		b = append(b, 63)
		b = append(b, bytes.Repeat([]byte{'a'}, 63)...)
	}
	b = append(b, 61)
	b = append(b, bytes.Repeat([]byte{'b'}, 61)...)
	b = append(b, 0)
	if len(b) != 255 {
		t.Fatal(len(b))
	}
	name, n, err := readName(b, 0)
	if err != nil || n != 255 || CountLabels(name) != 4 {
		t.Fatalf("%v %d", err, n)
	}
	// one more byte is too much
	b2 := append([]byte{1, 'c'}, b...)
	if _, _, err := readName(b2, 0); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("got %v", err)
	}
}

func TestEncodeRejectsBadNames(t *testing.T) {
	long := strings.Repeat("a", 64) + ".com."
	for name, want := range map[string]error{
		long:    ErrLabelTooLong,
		"a..b.": ErrEmptyLabel,
		strings.Repeat("abcdefghi.", 30) + "com.": ErrNameTooLong,
		`a\`:       ErrBadEscape,
		`a\999.b.`: ErrBadEscape,
	} {
		if err := ValidName(name); !errors.Is(err, want) {
			t.Errorf("%.20q: got %v want %v", name, err, want)
		}
	}
}

func TestMaliciousTruncatedPackets(t *testing.T) {
	good, err := (&Message{
		Questions: []Question{{"example.com.", TypeMX, ClassIN}},
		Answers: []RR{{Name: "example.com.", Class: ClassIN, TTL: 5, Data: MX{5, "mx.example.com."}},
			{Name: "example.com.", Class: ClassIN, TTL: 5, Data: TXT{[]string{"hello"}}}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(good); i++ {
		if _, err := Unpack(good[:i]); err == nil {
			t.Fatalf("prefix of %d/%d bytes decoded without error", i, len(good))
		}
	}
	if _, err := Unpack(good); err != nil {
		t.Fatal(err)
	}
}

func TestHugeCountsRejectedEarly(t *testing.T) {
	b := []byte{0, 1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := Unpack(b); !errors.Is(err, ErrShort) {
		t.Fatalf("got %v", err)
	}
}

func TestRDataLengthMismatch(t *testing.T) {
	// A record claiming 5 bytes of rdata.
	b := append(hdr(0, 1), 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4, 5)
	if _, err := Unpack(b); !errors.Is(err, ErrRData) {
		t.Fatalf("got %v", err)
	}
	// TXT whose string overruns rdata.
	b = append(hdr(0, 1), 0, 0, 16, 0, 1, 0, 0, 0, 1, 0, 3, 9, 'a', 'b')
	if _, err := Unpack(b); !errors.Is(err, ErrRData) {
		t.Fatalf("got %v", err)
	}
}

func TestRDataOverrunThroughName(t *testing.T) {
	// NS rdata of length 2 whose name (label of 5) runs beyond rdlength.
	b := append(hdr(0, 1), 0, 0, 2, 0, 1, 0, 0, 0, 1, 0, 2, 5, 'a', 'b', 'c', 'd', 'e', 0)
	if _, err := Unpack(b); !errors.Is(err, ErrRData) {
		t.Fatalf("got %v", err)
	}
}

func TestUnpackNeverPanicsOnGarbage(t *testing.T) {
	seed := uint32(12345)
	for i := 0; i < 2000; i++ {
		n := int(seed>>3) % 80
		b := make([]byte, n)
		for j := range b {
			seed = seed*1664525 + 1013904223
			b[j] = byte(seed >> 24)
		}
		_, _ = Unpack(b)
	}
}

func TestReverseNameIPv4(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("1.2.3.4")); got != "4.3.2.1.in-addr.arpa." {
		t.Fatal(got)
	}
}

func TestReverseNameIPv6Nibbles(t *testing.T) {
	got := ReverseName(netip.MustParseAddr("2001:db8::567:89ab"))
	want := "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestNameHelpers(t *testing.T) {
	if !IsSubdomain("WWW.Example.COM", "example.com.") || IsSubdomain("badexample.com.", "example.com.") || !IsSubdomain("x.", ".") {
		t.Fatal("IsSubdomain")
	}
	if ParentName("a.b.c.") != "b.c." || ParentName("com.") != "." || ParentName(".") != "." {
		t.Fatal("ParentName")
	}
	if CanonicalName("ExAmple.COM") != "example.com." || FQDN("") != "." {
		t.Fatal("canonical")
	}
	if CountLabels(".") != 0 || CountLabels("a.b.") != 2 {
		t.Fatal("CountLabels")
	}
}

func TestEscapedLabelRoundTrip(t *testing.T) {
	name := `a\.b.example.com.`
	labels, err := parseName(name)
	if err != nil || len(labels) != 3 || string(labels[0]) != "a.b" {
		t.Fatalf("%q %v", labels, err)
	}
	rr := roundTrip(t, CNAME{`sp\032ace.\000nul.example.`})
	if rr.Data.(CNAME).Target != `sp\032ace.\000nul.example.` {
		t.Fatal(rr.Data)
	}
	m := &Message{Questions: []Question{{name, TypeA, ClassIN}}}
	wire, _ := m.Pack()
	got, _ := Unpack(wire)
	if got.Questions[0].Name != name {
		t.Fatal(got.Questions[0].Name)
	}
}

func TestTypeAndClassNames(t *testing.T) {
	if ty, ok := ParseType("mx"); !ok || ty != TypeMX {
		t.Fatal("mx")
	}
	if ty, ok := ParseType("TYPE65"); !ok || ty != 65 {
		t.Fatal("TYPE65")
	}
	if _, ok := ParseType("bogus"); ok {
		t.Fatal("bogus")
	}
	if TypeCAA.String() != "CAA" || Type(4242).String() != "TYPE4242" || ClassIN.String() != "IN" || Class(9).String() != "CLASS9" {
		t.Fatal("names")
	}
	if RCodeNameError.String() != "NXDOMAIN" || RCode(9).String() != "RCODE9" || OpcodeQuery.String() != "QUERY" {
		t.Fatal("rcode/opcode")
	}
}

func TestPackRejectsWrongFamily(t *testing.T) {
	bad := []RData{A{netip.MustParseAddr("::1")}, AAAA{netip.MustParseAddr("1.2.3.4")}}
	for _, d := range bad {
		m := &Message{Answers: []RR{{Name: "a.", Class: ClassIN, Data: d}}}
		if _, err := m.Pack(); err == nil {
			t.Errorf("%T should fail", d)
		}
	}
}

func TestAllSectionsRoundTrip(t *testing.T) {
	m := &Message{
		Header:      Header{ID: 9, Response: true, Authoritative: true},
		Questions:   []Question{{"example.com.", TypeNS, ClassIN}},
		Answers:     []RR{{Name: "example.com.", Class: ClassIN, TTL: 10, Data: NS{"a.iana-servers.net."}}},
		Authorities: []RR{{Name: "example.com.", Class: ClassIN, TTL: 10, Data: SOA{"ns.icann.org.", "noc.dns.icann.org.", 1, 2, 3, 4, 5}}},
		Additionals: []RR{{Name: "a.iana-servers.net.", Class: ClassIN, TTL: 10, Data: A{netip.MustParseAddr("199.43.135.53")}}},
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(wire)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("%v\n%+v\n%+v", err, got, m)
	}
}
