package resolver

import "net/netip"

// RootServer is one entry of the root hints file.
type RootServer struct {
	Name string
	V4   netip.Addr
	V6   netip.Addr
}

func rs(name, v4, v6 string) RootServer {
	return RootServer{name + ".root-servers.net.", netip.MustParseAddr(v4), netip.MustParseAddr(v6)}
}

// RootServers is the built-in root hints (https://www.iana.org/domains/root/files).
var RootServers = []RootServer{
	rs("a", "198.41.0.4", "2001:503:ba3e::2:30"),
	rs("b", "170.247.170.2", "2801:1b8:10::b"),
	rs("c", "192.33.4.12", "2001:500:2::c"),
	rs("d", "199.7.91.13", "2001:500:2d::d"),
	rs("e", "192.203.230.10", "2001:500:a8::e"),
	rs("f", "192.5.5.241", "2001:500:2f::f"),
	rs("g", "192.112.36.4", "2001:500:12::d0d"),
	rs("h", "198.97.190.53", "2001:500:1::53"),
	rs("i", "192.36.148.17", "2001:7fe::53"),
	rs("j", "192.58.128.30", "2001:503:c27::2:30"),
	rs("k", "193.0.14.129", "2001:7fd::1"),
	rs("l", "199.7.83.42", "2001:500:9f::42"),
	rs("m", "202.12.27.33", "2001:dc3::35"),
}
