package http

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestClientNetworkListenerConfiguration(t *testing.T) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	unrestricted, err := restrictClientNetworks(base, nil)
	if err != nil || unrestricted != base {
		t.Fatalf("empty configuration must preserve existing listener: %v", err)
	}
	for _, cidr := range []string{"", "not-a-network", "192.0.2.1", "0.0.0.0/0", "::/0", "192.0.2.1/24", "::ffff:192.0.2.0/120"} {
		t.Run(cidr, func(t *testing.T) {
			if _, err := restrictClientNetworks(base, []string{cidr}); err == nil {
				t.Fatal("unsafe or malformed CIDR must fail closed")
			}
		})
	}
}

func TestClientNetworkListenerRejectsSocketSourceAndIgnoresForwardedHeaders(t *testing.T) {
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := restrictClientNetworks(base, []string{"127.0.0.1/32"})
	if err != nil {
		base.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(guarded) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-finished; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server: %v", err)
		}
	})

	deniedDialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
	denied, err := deniedDialer.Dial("tcp4", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	denied.SetDeadline(time.Now().Add(time.Second))
	_, _ = io.WriteString(denied, "GET /health HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\n\r\n")
	reply := make([]byte, 128)
	count, err := denied.Read(reply)
	if count != 0 || err == nil {
		t.Fatalf("denied socket received application bytes: %q (%v)", reply[:count], err)
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("denied connection must close promptly, not time out")
	}

	transport := &http.Transport{DialContext: (&net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, Timeout: time.Second,
	}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("http://" + base.Addr().String() + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("allowed source returned %d", response.StatusCode)
	}
}

type networkTestConn struct {
	net.Conn
	address net.Addr
}

func (c *networkTestConn) RemoteAddr() net.Addr { return c.address }

type networkTestListener struct {
	connection net.Conn
}

func (l *networkTestListener) Accept() (net.Conn, error) {
	if l.connection == nil {
		return nil, net.ErrClosed
	}
	connection := l.connection
	l.connection = nil
	return connection, nil
}
func (l *networkTestListener) Close() error { return nil }
func (l *networkTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}

func TestClientNetworkListenerPreservesTLSConnectionAndMapsIPv4(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	tlsConnection := tls.Server(&networkTestConn{Conn: left, address: &net.TCPAddr{
		IP: net.ParseIP("::ffff:192.0.2.5"), Port: 1234,
	}}, &tls.Config{MinVersion: tls.VersionTLS12})
	guarded, err := restrictClientNetworks(&networkTestListener{connection: tlsConnection}, []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := guarded.Accept()
	if err != nil || accepted != tlsConnection {
		t.Fatalf("guard must preserve *tls.Conn for net/http TLS detection: %T %v", accepted, err)
	}
}

func TestClientNetworkListenerRejectsUnknownRemoteAddress(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	guarded, err := restrictClientNetworks(&networkTestListener{connection: left}, []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := guarded.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("unparseable socket source must be closed: %v", err)
	}
}
