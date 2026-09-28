package dnsmsg

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RData is the type-specific part of a resource record.
type RData interface {
	Type() Type
	// String returns the presentation format of the data.
	String() string
	pack(b *builder) error
}

// A is an IPv4 address record.
type A struct{ Addr netip.Addr }

// AAAA is an IPv6 address record.
type AAAA struct{ Addr netip.Addr }

// CNAME is a canonical name alias.
type CNAME struct{ Target string }

// NS names an authoritative server.
type NS struct{ Host string }

// PTR points to a name, used for reverse lookups.
type PTR struct{ Host string }

// MX is a mail exchanger.
type MX struct {
	Pref uint16
	Host string
}

// TXT holds one or more character strings.
type TXT struct{ Strings []string }

// SOA is the start of authority record.
type SOA struct {
	MName, RName                            string
	Serial, Refresh, Retry, Expire, Minimum uint32
}

// SRV locates a service.
type SRV struct {
	Priority, Weight, Port uint16
	Target                 string
}

// CAA restricts which CAs may issue certificates.
type CAA struct {
	Flag  uint8
	Tag   string
	Value string
}

// EDNSOption is one option inside an OPT record.
type EDNSOption struct {
	Code uint16
	Data []byte
}

// OPT is the EDNS0 pseudo record data (RFC 6891). The UDP size and flags live
// in the Class and TTL fields of the enclosing RR.
type OPT struct{ Options []EDNSOption }

// Unknown carries data of a type godig has no parser for (RFC 3597).
type Unknown struct {
	T    Type
	Data []byte
}

func (A) Type() Type         { return TypeA }
func (AAAA) Type() Type      { return TypeAAAA }
func (CNAME) Type() Type     { return TypeCNAME }
func (NS) Type() Type        { return TypeNS }
func (PTR) Type() Type       { return TypePTR }
func (MX) Type() Type        { return TypeMX }
func (TXT) Type() Type       { return TypeTXT }
func (SOA) Type() Type       { return TypeSOA }
func (SRV) Type() Type       { return TypeSRV }
func (CAA) Type() Type       { return TypeCAA }
func (OPT) Type() Type       { return TypeOPT }
func (u Unknown) Type() Type { return u.T }

func (r A) String() string     { return r.Addr.String() }
func (r AAAA) String() string  { return r.Addr.String() }
func (r CNAME) String() string { return r.Target }
func (r NS) String() string    { return r.Host }
func (r PTR) String() string   { return r.Host }
func (r MX) String() string    { return fmt.Sprintf("%d %s", r.Pref, r.Host) }
func (r TXT) String() string {
	parts := make([]string, len(r.Strings))
	for i, s := range r.Strings {
		parts[i] = quoteText(s)
	}
	return strings.Join(parts, " ")
}
func (r SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", r.MName, r.RName, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum)
}
func (r SRV) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
}
func (r CAA) String() string {
	return fmt.Sprintf("%d %s %s", r.Flag, r.Tag, quoteText(r.Value))
}
func (r OPT) String() string {
	parts := make([]string, len(r.Options))
	for i, o := range r.Options {
		parts[i] = fmt.Sprintf("%d:%s", o.Code, hex.EncodeToString(o.Data))
	}
	return strings.Join(parts, " ")
}

// String uses the RFC 3597 generic format: \# <length> <hex>.
func (u Unknown) String() string {
	if len(u.Data) == 0 {
		return `\# 0`
	}
	return fmt.Sprintf(`\# %d %s`, len(u.Data), hex.EncodeToString(u.Data))
}

func quoteText(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&sb, "\\%03d", c)
		default:
			sb.WriteByte(c)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// ---- packing ----

func (r A) pack(b *builder) error {
	if !r.Addr.Is4() {
		return fmt.Errorf("dnsmsg: A record needs an IPv4 address, got %v", r.Addr)
	}
	a := r.Addr.As4()
	b.buf = append(b.buf, a[:]...)
	return nil
}

func (r AAAA) pack(b *builder) error {
	if !r.Addr.Is6() || r.Addr.Is4In6() {
		return fmt.Errorf("dnsmsg: AAAA record needs an IPv6 address, got %v", r.Addr)
	}
	a := r.Addr.As16()
	b.buf = append(b.buf, a[:]...)
	return nil
}

func (r CNAME) pack(b *builder) error { return b.name(r.Target, true) }
func (r NS) pack(b *builder) error    { return b.name(r.Host, true) }
func (r PTR) pack(b *builder) error   { return b.name(r.Host, true) }

func (r MX) pack(b *builder) error {
	b.u16(r.Pref)
	return b.name(r.Host, true)
}

func (r TXT) pack(b *builder) error {
	if len(r.Strings) == 0 {
		b.buf = append(b.buf, 0)
		return nil
	}
	for _, s := range r.Strings {
		if err := b.charString(s); err != nil {
			return err
		}
	}
	return nil
}

func (r SOA) pack(b *builder) error {
	if err := b.name(r.MName, true); err != nil {
		return err
	}
	if err := b.name(r.RName, true); err != nil {
		return err
	}
	b.u32(r.Serial)
	b.u32(r.Refresh)
	b.u32(r.Retry)
	b.u32(r.Expire)
	b.u32(r.Minimum)
	return nil
}

func (r SRV) pack(b *builder) error {
	b.u16(r.Priority)
	b.u16(r.Weight)
	b.u16(r.Port)
	return b.name(r.Target, false) // RFC 2782: no compression
}

func (r CAA) pack(b *builder) error {
	if len(r.Tag) == 0 || len(r.Tag) > 255 {
		return ErrTooLarge
	}
	b.buf = append(b.buf, r.Flag, byte(len(r.Tag)))
	b.buf = append(b.buf, r.Tag...)
	b.buf = append(b.buf, r.Value...)
	return nil
}

func (r OPT) pack(b *builder) error {
	for _, o := range r.Options {
		if len(o.Data) > 0xffff {
			return ErrTooLarge
		}
		b.u16(o.Code)
		b.u16(uint16(len(o.Data)))
		b.buf = append(b.buf, o.Data...)
	}
	return nil
}

func (u Unknown) pack(b *builder) error {
	b.buf = append(b.buf, u.Data...)
	return nil
}

// ---- unpacking ----

// unpackRData parses the data of a record of type t occupying msg[off:end].
func unpackRData(t Type, msg []byte, off, end int) (RData, error) {
	var (
		rd  RData
		err error
		n   = off
	)
	switch t {
	case TypeA:
		if end-off != 4 {
			return nil, ErrRData
		}
		rd = A{netip.AddrFrom4([4]byte(msg[off:end]))}
		n = end
	case TypeAAAA:
		if end-off != 16 {
			return nil, ErrRData
		}
		rd = AAAA{netip.AddrFrom16([16]byte(msg[off:end]))}
		n = end
	case TypeCNAME, TypeNS, TypePTR:
		var s string
		s, n, err = readName(msg, off)
		switch t {
		case TypeCNAME:
			rd = CNAME{s}
		case TypeNS:
			rd = NS{s}
		default:
			rd = PTR{s}
		}
	case TypeMX:
		if end-off < 3 {
			return nil, ErrRData
		}
		var h string
		h, n, err = readName(msg, off+2)
		rd = MX{binary.BigEndian.Uint16(msg[off:]), h}
	case TypeTXT:
		var ss []string
		for n < end {
			l := int(msg[n])
			if n+1+l > end {
				return nil, ErrRData
			}
			ss = append(ss, string(msg[n+1:n+1+l]))
			n += 1 + l
		}
		rd = TXT{ss}
	case TypeSOA:
		var s SOA
		if s.MName, n, err = readName(msg, off); err != nil {
			return nil, err
		}
		if s.RName, n, err = readName(msg, n); err != nil {
			return nil, err
		}
		if end-n != 20 {
			return nil, ErrRData
		}
		s.Serial = binary.BigEndian.Uint32(msg[n:])
		s.Refresh = binary.BigEndian.Uint32(msg[n+4:])
		s.Retry = binary.BigEndian.Uint32(msg[n+8:])
		s.Expire = binary.BigEndian.Uint32(msg[n+12:])
		s.Minimum = binary.BigEndian.Uint32(msg[n+16:])
		n = end
		rd = s
	case TypeSRV:
		if end-off < 7 {
			return nil, ErrRData
		}
		s := SRV{
			Priority: binary.BigEndian.Uint16(msg[off:]),
			Weight:   binary.BigEndian.Uint16(msg[off+2:]),
			Port:     binary.BigEndian.Uint16(msg[off+4:]),
		}
		s.Target, n, err = readName(msg, off+6)
		rd = s
	case TypeCAA:
		if end-off < 2 {
			return nil, ErrRData
		}
		tl := int(msg[off+1])
		if tl == 0 || off+2+tl > end {
			return nil, ErrRData
		}
		rd = CAA{Flag: msg[off], Tag: string(msg[off+2 : off+2+tl]), Value: string(msg[off+2+tl : end])}
		n = end
	case TypeOPT:
		var o OPT
		for n < end {
			if n+4 > end {
				return nil, ErrRData
			}
			code := binary.BigEndian.Uint16(msg[n:])
			l := int(binary.BigEndian.Uint16(msg[n+2:]))
			if n+4+l > end {
				return nil, ErrRData
			}
			o.Options = append(o.Options, EDNSOption{code, append([]byte(nil), msg[n+4:n+4+l]...)})
			n += 4 + l
		}
		rd = o
	default:
		rd = Unknown{t, append([]byte(nil), msg[off:end]...)}
		n = end
	}
	if err != nil {
		return nil, err
	}
	if n != end {
		return nil, ErrRData
	}
	return rd, nil
}

// ParseUnknown parses the RFC 3597 "\# len hex" presentation format.
func ParseUnknown(t Type, s string) (Unknown, error) {
	f := strings.Fields(s)
	if len(f) < 2 || f[0] != `\#` {
		return Unknown{}, ErrRData
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 0 {
		return Unknown{}, ErrRData
	}
	data, err := hex.DecodeString(strings.Join(f[2:], ""))
	if err != nil || len(data) != n {
		return Unknown{}, ErrRData
	}
	return Unknown{t, data}, nil
}
