package http

import (
	"fmt"
	"net"
	"net/netip"
)

type clientNetworkListener struct {
	net.Listener
	allowed []netip.Prefix
}

// restrictClientNetworks checks the actual TCP peer before net/http or TLS
// processing. It never uses forwarding headers and preserves accepted *tls.Conn
// values so net/http can perform its normal TLS handshake and protocol handling.
func restrictClientNetworks(listener net.Listener, cidrs []string) (net.Listener, error) {
	if len(cidrs) == 0 {
		return listener, nil
	}
	allowed := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return nil, fmt.Errorf("server.allowedClientCIDRs must contain explicit canonical CIDRs, without wildcard networks")
		}
		allowed = append(allowed, prefix)
	}
	switch listener.Addr().Network() {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("server.allowedClientCIDRs requires a TCP listener")
	}
	return &clientNetworkListener{Listener: listener, allowed: allowed}, nil
}

func (listener *clientNetworkListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if listener.allows(connection.RemoteAddr()) {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func (listener *clientNetworkListener) allows(address net.Addr) bool {
	if address == nil {
		return false
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range listener.allowed {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
