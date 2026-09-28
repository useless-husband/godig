package dnsmsg

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Decoding and encoding errors.
var (
	ErrShort        = errors.New("dnsmsg: message truncated")
	ErrBadPointer   = errors.New("dnsmsg: compression pointer does not point backwards")
	ErrPointerLoop  = errors.New("dnsmsg: too many compression pointers (loop)")
	ErrBadLabel     = errors.New("dnsmsg: unsupported label type")
	ErrLabelTooLong = errors.New("dnsmsg: label longer than 63 bytes")
	ErrNameTooLong  = errors.New("dnsmsg: name longer than 255 bytes")
	ErrEmptyLabel   = errors.New("dnsmsg: empty label in name")
	ErrBadEscape    = errors.New("dnsmsg: bad escape in name")
	ErrRData        = errors.New("dnsmsg: malformed record data")
	ErrTooLarge     = errors.New("dnsmsg: value too large to encode")
)

const (
	maxLabel    = 63
	maxWireName = 255
	maxJumps    = 16
)

// parseName converts presentation format ("www.Example.com.", with \. and
// \DDD escapes) to raw labels.
func parseName(s string) ([][]byte, error) {
	if s == "" || s == "." {
		return nil, nil
	}
	var labels [][]byte
	var cur []byte
	wire := 1
	flush := func() error {
		if len(cur) == 0 {
			return ErrEmptyLabel
		}
		if len(cur) > maxLabel {
			return ErrLabelTooLong
		}
		wire += len(cur) + 1
		if wire > maxWireName {
			return ErrNameTooLong
		}
		labels = append(labels, cur)
		cur = nil
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '.':
			if err := flush(); err != nil {
				return nil, err
			}
		case '\\':
			if i+1 >= len(s) {
				return nil, ErrBadEscape
			}
			n := s[i+1]
			if n >= '0' && n <= '9' {
				if i+3 >= len(s) {
					return nil, ErrBadEscape
				}
				d1, d2, d3 := s[i+1]-'0', s[i+2]-'0', s[i+3]-'0'
				if d1 > 9 || d2 > 9 || d3 > 9 {
					return nil, ErrBadEscape
				}
				v := int(d1)*100 + int(d2)*10 + int(d3)
				if v > 255 {
					return nil, ErrBadEscape
				}
				cur = append(cur, byte(v))
				i += 3
			} else {
				cur = append(cur, n)
				i++
			}
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return labels, nil
}

func appendEscaped(sb *strings.Builder, label []byte) {
	for _, b := range label {
		switch {
		case b == '.' || b == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(b)
		case b <= 0x20 || b >= 0x7f:
			fmt.Fprintf(sb, "\\%03d", b)
		default:
			sb.WriteByte(b)
		}
	}
}

// ValidName reports whether s can be encoded as a DNS name.
func ValidName(s string) error {
	_, err := parseName(s)
	return err
}

// FQDN returns s with a trailing dot.
func FQDN(s string) string {
	if s == "" {
		return "."
	}
	if strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "\\.") {
		return s
	}
	return s + "."
}

// CanonicalName returns the lower-cased fully qualified form of s, used for
// comparisons and cache keys.
func CanonicalName(s string) string {
	return strings.ToLower(FQDN(s))
}

// EqualNames compares two names ignoring ASCII case and a missing trailing dot.
func EqualNames(a, b string) bool {
	return CanonicalName(a) == CanonicalName(b)
}

// IsSubdomain reports whether child is equal to or below parent.
func IsSubdomain(child, parent string) bool {
	c, p := CanonicalName(child), CanonicalName(parent)
	if p == "." || c == p {
		return true
	}
	return strings.HasSuffix(c, "."+p)
}

// CountLabels returns the number of labels in a name ("." has zero).
func CountLabels(s string) int {
	l, _ := parseName(s)
	return len(l)
}

// ParentName removes the leftmost label; the parent of "." is ".".
func ParentName(s string) string {
	l, err := parseName(s)
	if err != nil || len(l) <= 1 {
		return "."
	}
	var sb strings.Builder
	for _, x := range l[1:] {
		appendEscaped(&sb, x)
		sb.WriteByte('.')
	}
	return sb.String()
}

// ReverseName returns the PTR owner name for an address: in-addr.arpa for
// IPv4 and the nibble format under ip6.arpa for IPv6.
func ReverseName(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	const hex = "0123456789abcdef"
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa.")
	return sb.String()
}

// readName decodes a possibly compressed name starting at off. It returns the
// name and the offset of the first byte after the name in the original
// position (not following pointers).
//
// A compression pointer must point strictly before the pointer itself;
// pointers to the future or to themselves are rejected, and the number of
// jumps is bounded so that a chain of labels and pointers that cycles back
// cannot loop forever.
func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	pos, end, jumps, wire := off, -1, 0, 1
	for {
		if pos >= len(msg) {
			return "", 0, ErrShort
		}
		c := msg[pos]
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if end < 0 {
					end = pos + 1
				}
				if sb.Len() == 0 {
					sb.WriteByte('.')
				}
				return sb.String(), end, nil
			}
			n := int(c)
			if pos+1+n > len(msg) {
				return "", 0, ErrShort
			}
			wire += n + 1
			if wire > maxWireName {
				return "", 0, ErrNameTooLong
			}
			appendEscaped(&sb, msg[pos+1:pos+1+n])
			sb.WriteByte('.')
			pos += 1 + n
		case 0xC0:
			if pos+1 >= len(msg) {
				return "", 0, ErrShort
			}
			ptr := int(c&0x3F)<<8 | int(msg[pos+1])
			if end < 0 {
				end = pos + 2
			}
			if ptr >= pos {
				return "", 0, ErrBadPointer
			}
			jumps++
			if jumps > maxJumps {
				return "", 0, ErrPointerLoop
			}
			pos = ptr
		default:
			return "", 0, ErrBadLabel
		}
	}
}
