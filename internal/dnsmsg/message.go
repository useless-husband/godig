package dnsmsg

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DefaultUDPSize is the EDNS0 UDP payload size godig advertises (DNS flag
// day 2020 recommendation, avoids IP fragmentation).
const DefaultUDPSize = 1232

// Header holds the flags of a message. Counts are derived from the sections.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             Opcode
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Zero               bool
	AuthenticData      bool
	CheckingDisabled   bool
	RCode              RCode
}

// Question is an entry of the question section.
type Question struct {
	Name  string
	Type  Type
	Class Class
}

func (q Question) String() string { return fmt.Sprintf("%s\t%s\t%s", q.Name, q.Class, q.Type) }

// RR is a resource record. For OPT records Class is the requestor's UDP
// payload size and TTL packs the extended RCODE, version and flags.
type RR struct {
	Name  string
	Class Class
	TTL   uint32
	Data  RData
}

// Type returns the record type of the data.
func (r RR) Type() Type { return r.Data.Type() }

// String renders the record in zone-file style with tab separators.
func (r RR) String() string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", r.Name, r.TTL, r.Class, r.Type(), r.Data)
}

// Message is a DNS message.
type Message struct {
	Header
	Questions   []Question
	Answers     []RR
	Authorities []RR
	Additionals []RR
}

// NewQuery builds a standard query with one question. edns adds an OPT record
// advertising DefaultUDPSize.
func NewQuery(id uint16, name string, t Type, rd, edns bool) *Message {
	m := &Message{
		Header:    Header{ID: id, RecursionDesired: rd},
		Questions: []Question{{Name: FQDN(name), Type: t, Class: ClassIN}},
	}
	if edns {
		m.SetEDNS(DefaultUDPSize, false)
	}
	return m
}

// SetEDNS replaces any OPT record with one advertising the given UDP size.
func (m *Message) SetEDNS(size uint16, do bool) {
	kept := m.Additionals[:0:0]
	for _, rr := range m.Additionals {
		if rr.Type() != TypeOPT {
			kept = append(kept, rr)
		}
	}
	var ttl uint32
	if do {
		ttl = 0x8000
	}
	m.Additionals = append(kept, RR{Name: ".", Class: Class(size), TTL: ttl, Data: OPT{}})
}

// OPTRecord returns the EDNS0 pseudo record, if any.
func (m *Message) OPTRecord() (RR, bool) {
	for _, rr := range m.Additionals {
		if rr.Type() == TypeOPT {
			return rr, true
		}
	}
	return RR{}, false
}

// UDPSize is the payload size the sender can accept over UDP.
func (m *Message) UDPSize() int {
	if rr, ok := m.OPTRecord(); ok {
		if s := int(rr.Class); s > 512 {
			return s
		}
	}
	return 512
}

func (h Header) flags() uint16 {
	var f uint16
	set := func(b bool, bit uint) {
		if b {
			f |= 1 << bit
		}
	}
	set(h.Response, 15)
	f |= uint16(h.Opcode&0xF) << 11
	set(h.Authoritative, 10)
	set(h.Truncated, 9)
	set(h.RecursionDesired, 8)
	set(h.RecursionAvailable, 7)
	set(h.Zero, 6)
	set(h.AuthenticData, 5)
	set(h.CheckingDisabled, 4)
	f |= uint16(h.RCode & 0xF)
	return f
}

func headerFromFlags(id, f uint16) Header {
	bit := func(n uint) bool { return f&(1<<n) != 0 }
	return Header{
		ID: id, Response: bit(15), Opcode: Opcode(f >> 11 & 0xF),
		Authoritative: bit(10), Truncated: bit(9), RecursionDesired: bit(8),
		RecursionAvailable: bit(7), Zero: bit(6), AuthenticData: bit(5),
		CheckingDisabled: bit(4), RCode: RCode(f & 0xF),
	}
}

// builder accumulates a wire-format message with name compression.
type builder struct {
	buf  []byte
	comp map[string]int
}

func (b *builder) u16(v uint16) { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *builder) u32(v uint32) { b.buf = binary.BigEndian.AppendUint32(b.buf, v) }

func (b *builder) charString(s string) error {
	if len(s) > 255 {
		return ErrTooLarge
	}
	b.buf = append(b.buf, byte(len(s)))
	b.buf = append(b.buf, s...)
	return nil
}

// name appends a domain name. With compress set, any suffix already written
// is replaced by a two-byte pointer and new suffixes are remembered.
func (b *builder) name(s string, compress bool) error {
	labels, err := parseName(s)
	if err != nil {
		return err
	}
	compress = compress && b.comp != nil
	// keys[i] identifies the suffix starting at labels[i], case-insensitively.
	keys := make([]string, len(labels))
	suffix := ""
	for i := len(labels) - 1; i >= 0; i-- {
		suffix = string(rune(len(labels[i]))) + strings.ToLower(string(labels[i])) + suffix
		keys[i] = suffix
	}
	for i, l := range labels {
		if compress {
			if off, ok := b.comp[keys[i]]; ok {
				b.u16(0xC000 | uint16(off))
				return nil
			}
			if len(b.buf) < 0x3FFF {
				b.comp[keys[i]] = len(b.buf)
			}
		}
		b.buf = append(b.buf, byte(len(l)))
		b.buf = append(b.buf, l...)
	}
	b.buf = append(b.buf, 0)
	return nil
}

func (b *builder) rr(r RR) error {
	if r.Data == nil {
		return fmt.Errorf("dnsmsg: record %q has no data", r.Name)
	}
	if err := b.name(r.Name, true); err != nil {
		return err
	}
	b.u16(uint16(r.Type()))
	b.u16(uint16(r.Class))
	b.u32(r.TTL)
	lenAt := len(b.buf)
	b.u16(0)
	if err := r.Data.pack(b); err != nil {
		return err
	}
	n := len(b.buf) - lenAt - 2
	if n > 0xffff {
		return ErrTooLarge
	}
	binary.BigEndian.PutUint16(b.buf[lenAt:], uint16(n))
	return nil
}

// Pack encodes the message with name compression.
func (m *Message) Pack() ([]byte, error) {
	for _, n := range []int{len(m.Questions), len(m.Answers), len(m.Authorities), len(m.Additionals)} {
		if n > 0xffff {
			return nil, ErrTooLarge
		}
	}
	b := &builder{buf: make([]byte, 0, 512), comp: map[string]int{}}
	b.u16(m.ID)
	b.u16(m.Header.flags())
	b.u16(uint16(len(m.Questions)))
	b.u16(uint16(len(m.Answers)))
	b.u16(uint16(len(m.Authorities)))
	b.u16(uint16(len(m.Additionals)))
	for _, q := range m.Questions {
		if err := b.name(q.Name, true); err != nil {
			return nil, err
		}
		b.u16(uint16(q.Type))
		b.u16(uint16(q.Class))
	}
	for _, sec := range [][]RR{m.Answers, m.Authorities, m.Additionals} {
		for _, r := range sec {
			if err := b.rr(r); err != nil {
				return nil, err
			}
		}
	}
	return b.buf, nil
}

// Unpack decodes a wire-format message. It never panics on malformed input.
func Unpack(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, ErrShort
	}
	m := &Message{Header: headerFromFlags(binary.BigEndian.Uint16(msg), binary.BigEndian.Uint16(msg[2:]))}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	counts := [3]int{
		int(binary.BigEndian.Uint16(msg[6:])),
		int(binary.BigEndian.Uint16(msg[8:])),
		int(binary.BigEndian.Uint16(msg[10:])),
	}
	// Every question needs at least 5 bytes and every record at least 11;
	// refuse absurd counts before allocating anything.
	if qd*5+(counts[0]+counts[1]+counts[2])*11 > len(msg)-12 {
		return nil, ErrShort
	}
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(msg) {
			return nil, ErrShort
		}
		m.Questions = append(m.Questions, Question{name, Type(binary.BigEndian.Uint16(msg[n:])), Class(binary.BigEndian.Uint16(msg[n+2:]))})
		off = n + 4
	}
	sections := []*[]RR{&m.Answers, &m.Authorities, &m.Additionals}
	for si, sec := range sections {
		for i := 0; i < counts[si]; i++ {
			rr, n, err := unpackRR(msg, off)
			if err != nil {
				return nil, err
			}
			*sec = append(*sec, rr)
			off = n
		}
	}
	return m, nil
}

func unpackRR(msg []byte, off int) (RR, int, error) {
	name, n, err := readName(msg, off)
	if err != nil {
		return RR{}, 0, err
	}
	if n+10 > len(msg) {
		return RR{}, 0, ErrShort
	}
	t := Type(binary.BigEndian.Uint16(msg[n:]))
	rr := RR{Name: name, Class: Class(binary.BigEndian.Uint16(msg[n+2:])), TTL: binary.BigEndian.Uint32(msg[n+4:])}
	rdlen := int(binary.BigEndian.Uint16(msg[n+8:]))
	start := n + 10
	if start+rdlen > len(msg) {
		return RR{}, 0, ErrShort
	}
	rr.Data, err = unpackRData(t, msg, start, start+rdlen)
	if err != nil {
		return RR{}, 0, err
	}
	return rr, start + rdlen, nil
}

// UnpackTruncated decodes as much of a possibly truncated message as it can.
// The header and question section must be intact; resource records are
// returned up to the first one that fails to decode. It is meant for replies
// with the TC bit set, where only the fact of truncation matters.
func UnpackTruncated(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, ErrShort
	}
	m := &Message{Header: headerFromFlags(binary.BigEndian.Uint16(msg), binary.BigEndian.Uint16(msg[2:]))}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(msg, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(msg) {
			return nil, ErrShort
		}
		m.Questions = append(m.Questions, Question{name, Type(binary.BigEndian.Uint16(msg[n:])), Class(binary.BigEndian.Uint16(msg[n+2:]))})
		off = n + 4
	}
	sections := []*[]RR{&m.Answers, &m.Authorities, &m.Additionals}
	for si, sec := range sections {
		want := int(binary.BigEndian.Uint16(msg[6+2*si:]))
		for i := 0; i < want; i++ {
			rr, n, err := unpackRR(msg, off)
			if err != nil {
				return m, nil
			}
			*sec = append(*sec, rr)
			off = n
		}
	}
	return m, nil
}

// MapNames applies f to every domain name in the message: question names,
// record owners and the names inside CNAME, NS, PTR, MX, SOA and SRV data.
// The message is modified in place.
func (m *Message) MapNames(f func(string) string) {
	for i := range m.Questions {
		m.Questions[i].Name = f(m.Questions[i].Name)
	}
	for _, sec := range []([]RR){m.Answers, m.Authorities, m.Additionals} {
		for i := range sec {
			sec[i].Name = f(sec[i].Name)
			switch d := sec[i].Data.(type) {
			case CNAME:
				sec[i].Data = CNAME{f(d.Target)}
			case NS:
				sec[i].Data = NS{f(d.Host)}
			case PTR:
				sec[i].Data = PTR{f(d.Host)}
			case MX:
				d.Host = f(d.Host)
				sec[i].Data = d
			case SOA:
				d.MName, d.RName = f(d.MName), f(d.RName)
				sec[i].Data = d
			case SRV:
				d.Target = f(d.Target)
				sec[i].Data = d
			}
		}
	}
}
