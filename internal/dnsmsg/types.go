// Package dnsmsg implements encoding and decoding of DNS messages (RFC 1035)
// together with the resource record types godig understands.
package dnsmsg

import (
	"strconv"
	"strings"
)

// Type is a resource record type.
type Type uint16

// Record types supported by name. Others are handled as opaque data (RFC 3597).
const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41
	TypeCAA   Type = 257
	TypeANY   Type = 255
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA",
	TypeSRV: "SRV", TypeOPT: "OPT", TypeCAA: "CAA", TypeANY: "ANY",
}

func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType accepts mnemonics ("mx") and the generic form ("TYPE65").
func ParseType(s string) (Type, bool) {
	s = strings.ToUpper(s)
	for t, n := range typeNames {
		if n == s {
			return t, true
		}
	}
	if strings.HasPrefix(s, "TYPE") {
		if v, err := strconv.ParseUint(s[4:], 10, 16); err == nil {
			return Type(v), true
		}
	}
	return 0, false
}

// Class is a DNS class.
type Class uint16

// Well-known classes.
const (
	ClassIN  Class = 1
	ClassCH  Class = 3
	ClassHS  Class = 4
	ClassANY Class = 255
)

func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	case ClassCH:
		return "CH"
	case ClassHS:
		return "HS"
	case ClassANY:
		return "ANY"
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// RCode is the 4-bit response code from the header.
type RCode uint8

// Response codes.
const (
	RCodeSuccess        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
)

func (r RCode) String() string {
	switch r {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormatError:
		return "FORMERR"
	case RCodeServerFailure:
		return "SERVFAIL"
	case RCodeNameError:
		return "NXDOMAIN"
	case RCodeNotImplemented:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// Opcode is the 4-bit operation code.
type Opcode uint8

// Opcodes.
const (
	OpcodeQuery  Opcode = 0
	OpcodeIQuery Opcode = 1
	OpcodeStatus Opcode = 2
	OpcodeNotify Opcode = 4
	OpcodeUpdate Opcode = 5
)

func (o Opcode) String() string {
	switch o {
	case OpcodeQuery:
		return "QUERY"
	case OpcodeIQuery:
		return "IQUERY"
	case OpcodeStatus:
		return "STATUS"
	case OpcodeNotify:
		return "NOTIFY"
	case OpcodeUpdate:
		return "UPDATE"
	}
	return "OPCODE" + strconv.Itoa(int(o))
}
