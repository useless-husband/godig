package dnsmsg

import (
	"bytes"
	"net/netip"
	"testing"
)

// FuzzUnpack checks that decoding never panics and that whatever decodes can
// be re-encoded into a stable form. The seed corpus lives in
// testdata/fuzz/FuzzUnpack and is what `go test` (and CI) runs; use
// `make fuzz` for real fuzzing.
func FuzzUnpack(f *testing.F) {
	good, _ := (&Message{
		Header:    Header{ID: 1, Response: true},
		Questions: []Question{{"example.com.", TypeA, ClassIN}},
		Answers: []RR{
			{Name: "example.com.", Class: ClassIN, TTL: 60, Data: A{netip.MustParseAddr("192.0.2.1")}},
			{Name: "example.com.", Class: ClassIN, TTL: 60, Data: MX{10, "mx.example.com."}},
			{Name: "example.com.", Class: ClassIN, TTL: 60, Data: TXT{[]string{"a", "b"}}},
		},
	}).Pack()
	f.Add(good)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Unpack(data)
		if err != nil {
			return
		}
		first, err := m.Pack()
		if err != nil {
			return // e.g. a name that only fits because of compression tricks
		}
		m2, err := Unpack(first)
		if err != nil {
			t.Fatalf("re-decode of own output failed: %v", err)
		}
		second, err := m2.Pack()
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("unstable encoding: %v\n%x\n%x", err, first, second)
		}
	})
}
