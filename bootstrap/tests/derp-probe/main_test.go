package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

type addressedConn struct {
	net.Conn
	remote net.Addr
}

func (c addressedConn) RemoteAddr() net.Addr { return c.remote }

type oneListener struct {
	conn   net.Conn
	used   atomic.Bool
	once   sync.Once
	closed chan struct{}
}

func (l *oneListener) Accept() (net.Conn, error) {
	if !l.used.Swap(true) {
		return l.conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *oneListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *oneListener) Addr() net.Addr { return &net.TCPAddr{Port: 18089} }
func testListener(t *testing.T, allowedIP string) (net.Conn, context.CancelFunc) {
	t.Helper()
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	ln := &oneListener{conn: addressedConn{a, &net.TCPAddr{IP: net.ParseIP("100.64.0.2"), Port: 4567}}, closed: make(chan struct{})}
	var allowed atomic.Value
	allowed.Store(allowedIP)
	go serve(ctx, ln, &allowed)
	_ = b.SetDeadline(time.Now().Add(time.Second))
	return b, cancel
}
func TestOnlyExactPeerGetsEcho(t *testing.T) {
	c, cancel := testListener(t, "100.64.0.2")
	defer cancel()
	defer c.Close()
	payload := bytes.Repeat([]byte{0xA7}, payloadSize)
	if _, err := io.Copy(c, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
}
func TestOtherPeerIsClosedWithoutReadingPayload(t *testing.T) {
	c, cancel := testListener(t, "100.64.0.3")
	defer cancel()
	defer c.Close()
	n, err := c.Write([]byte("not authorized"))
	if n != 0 || err == nil {
		t.Fatalf("accepted unknown peer: n=%d err=%v", n, err)
	}
}
func TestPartialRequestNeverGetsPartialSuccess(t *testing.T) {
	c, cancel := testListener(t, "100.64.0.2")
	defer cancel()
	defer c.Close()
	if _, err := c.Write([]byte("short")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 1)
	if n, err := c.Read(buf); n != 0 || err == nil {
		t.Fatal("partial request was echoed")
	}
}
func TestAmbiguousPeerIsRejected(t *testing.T) {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	for range 2 {
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{HostName: "infra-derp-test-other", Online: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}}
	}
	if _, err := findPeer(st, "infra-derp-test-other"); err == nil {
		t.Fatal("ambiguous hostname accepted")
	}
}
func TestSecretRedaction(t *testing.T) {
	privateAuth = "not-a-real-authentication-key"
	defer func() { privateAuth = "" }()
	if got := safeErr(&net.OpError{Op: privateAuth, Net: "tcp", Err: io.EOF}); bytes.Contains([]byte(got), []byte(privateAuth)) {
		t.Fatal("key leaked")
	}
}

// A coordinator reconnect can temporarily mark a cached peer offline while
// established DERP transports remain usable; attempt bytes instead of gating.
func TestOfflineControlStatusStillAttemptsPeer(t *testing.T) {
	peer := &ipnstate.PeerStatus{HostName: "infra-derp-test-other", Online: false, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}}
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): peer}}
	got, err := findPeer(st, peer.HostName)
	if err != nil || got != peer {
		t.Fatalf("control status suppressed a data probe: %v", err)
	}
}
