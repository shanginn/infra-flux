// derp-probe runs an isolated, ephemeral userspace peer, never a host VPN.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store"
	"tailscale.com/logtail"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
)

const payloadSize = 128 * 1024
const testPort = "18089"
const pinnedVersion = "v1.104.1"

var outMu sync.Mutex
var privateAuth string

func emit(kind string, fields map[string]any) {
	outMu.Lock()
	defer outMu.Unlock()
	fields["event"] = kind
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	_ = json.NewEncoder(os.Stdout).Encode(fields)
}
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if privateAuth != "" {
		s = strings.ReplaceAll(s, privateAuth, "[redacted]")
	}
	if len(s) > 1024 {
		s = s[:1024]
	}
	return s
}
func versionOK() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" {
			return dep.Version == pinnedVersion && dep.Replace == nil
		}
	}
	return false
}
func findPeer(st *ipnstate.Status, hostname string) (*ipnstate.PeerStatus, error) {
	var found *ipnstate.PeerStatus
	for _, p := range st.Peer {
		if p.HostName == hostname {
			if found != nil {
				return nil, errors.New("ambiguous peer hostname")
			}
			found = p
		}
	}
	if found == nil {
		return nil, errors.New("peer not present in netmap")
	}
	return found, nil
}
func peerIPv4(p *ipnstate.PeerStatus) (netip.Addr, error) {
	for _, a := range p.TailscaleIPs {
		if a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("peer has no IPv4 address")
}
func roundTrip(ctx context.Context, s *tsnet.Server, peer netip.Addr) (string, error) {
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	c, err := s.Dial(ctx, "tcp", net.JoinHostPort(peer.String(), testPort))
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = io.Copy(c, bytes.NewReader(payload)); err != nil {
		return "", err
	}
	received := make([]byte, payloadSize)
	if _, err = io.ReadFull(c, received); err != nil {
		return "", err
	}
	want := sha256.Sum256(payload)
	got := sha256.Sum256(received)
	if want != got {
		return "", errors.New("echo SHA256 mismatch")
	}
	return hex.EncodeToString(want[:]), nil
}
func serve(ctx context.Context, ln net.Listener, allowed *atomic.Value) {
	sem := make(chan struct{}, 2)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil || host != allowed.Load().(string) {
			_ = c.Close()
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-sem; _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			body := make([]byte, payloadSize)
			if _, err := io.ReadFull(c, body); err != nil {
				return
			}
			_, _ = io.Copy(c, bytes.NewReader(body))
		}()
	}
}
func run() error {
	control := flag.String("control-url", "", "self-hosted HTTPS coordinator URL")
	hostname := flag.String("hostname", "", "unique test hostname")
	peerName := flag.String("peer-hostname", "", "exact other test hostname")
	authPath := flag.String("auth-key-file", "", "0600 single-use ephemeral key file")
	stateDir := flag.String("state-dir", "", "private directory for this temporary instance")
	duration := flag.Duration("duration", 45*time.Minute, "lifetime, 1 minute to 2 hours")
	interval := flag.Duration("interval", 2*time.Second, "probe interval, 1 to 30 seconds")
	flag.Parse()
	u, err := url.Parse(*control)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("explicit HTTPS coordinator required")
	}
	if !strings.HasPrefix(*hostname, "infra-derp-test-") || !strings.HasPrefix(*peerName, "infra-derp-test-") || *hostname == *peerName {
		return errors.New("two distinct infra-derp-test- hostnames required")
	}
	if *duration < time.Minute || *duration > 2*time.Hour || *interval < time.Second || *interval > 30*time.Second {
		return errors.New("duration or interval outside bounds")
	}
	if !versionOK() {
		return errors.New("binary was not built with the pinned Tailscale module")
	}
	if os.Getenv("TS_DEBUG_ALWAYS_USE_DERP") != "true" || os.Getenv("TS_DEBUG_USE_DERP_ADDR") != "" {
		return errors.New("set only TS_DEBUG_ALWAYS_USE_DERP=true; DERP map override forbidden")
	}
	if *stateDir == "" || !filepath.IsAbs(*stateDir) {
		return errors.New("absolute private state-dir required")
	}
	fi, err := os.Stat(*stateDir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		return errors.New("state-dir must be private (0700)")
	}
	fi, err = os.Stat(*authPath)
	if err != nil {
		return err
	}
	privateKey := fi.Mode().Perm()&0077 == 0
	// systemd may expose a group-readable credential inside its restricted service credential mount.
	if credentialDir := os.Getenv("CREDENTIALS_DIRECTORY"); credentialDir != "" && filepath.Dir(*authPath) == credentialDir {
		parent, statErr := os.Stat(credentialDir)
		privateKey = statErr == nil && parent.IsDir() && parent.Mode().Perm()&0027 == 0 && fi.Mode().Perm()&0037 == 0
	}
	if !fi.Mode().IsRegular() || !privateKey || fi.Size() > 4096 {
		return fmt.Errorf("auth-key file rejected (mode=%o size=%d)", fi.Mode().Perm(), fi.Size())
	}
	keyBytes, err := os.ReadFile(*authPath)
	if err != nil {
		return err
	}
	auth := strings.TrimSpace(string(keyBytes))
	if len(auth) < 20 {
		return errors.New("invalid authentication key")
	}
	privateAuth = auth
	for i := range keyBytes {
		keyBytes[i] = 0
	}
	log.SetOutput(io.Discard)
	// Disable cloud log uploads before starting this self-hosted test client.
	logtail.Disable()
	baseCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(baseCtx, *duration)
	defer cancel()
	var udp4, udp6 atomic.Bool
	memStore, err := store.New(func(string, ...any) {}, "mem:")
	if err != nil {
		return err
	}
	server := &tsnet.Server{
		Dir: *stateDir, Store: memStore, Hostname: *hostname, Ephemeral: true,
		AuthKey: auth, ControlURL: *control,
		UserLogf: func(string, ...any) {},
		Logf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if strings.Contains(msg, "per TS_DEBUG_ALWAYS_USE_DERP") {
				if strings.Contains(msg, "udp4") {
					udp4.Store(true)
				}
				if strings.Contains(msg, "udp6") {
					udp6.Store(true)
				}
			}
		},
	}
	defer server.Close()
	readyCtx, readyCancel := context.WithTimeout(ctx, 90*time.Second)
	st, err := server.Up(readyCtx)
	readyCancel()
	if err != nil {
		return fmt.Errorf("ephemeral enrollment failed: %w", err)
	}
	if st.Self == nil {
		return errors.New("missing own identity")
	}
	if !udp4.Load() || !udp6.Load() {
		return errors.New("missing proof that both UDP transports are disabled")
	}
	lc, err := server.LocalClient()
	if err != nil {
		return err
	}
	defer func() {
		c, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = lc.Logout(c)
	}()
	emit("ready", map[string]any{"hostname": *hostname, "tailscale_version": pinnedVersion, "node_id": st.Self.ID, "node_key": st.Self.PublicKey.String(), "ips": st.TailscaleIPs, "relay": st.Self.Relay, "udp4_disabled": udp4.Load(), "udp6_disabled": udp6.Load(), "expires_after_seconds": duration.Seconds()})
	var allowed atomic.Value
	allowed.Store("")
	ln, err := server.Listen("tcp", ":"+testPort)
	if err != nil {
		return err
	}
	defer ln.Close()
	go serve(ctx, ln, &allowed)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	var sequence uint64
	for {
		select {
		case <-ctx.Done():
			emit("stopped", map[string]any{"reason": ctx.Err().Error(), "attempts": sequence})
			return nil
		case <-ticker.C:
		}
		sequence++
		start := time.Now()
		f := map[string]any{"hostname": *hostname, "peer_hostname": *peerName, "sequence": sequence, "bytes": payloadSize}
		attemptCtx, done := context.WithTimeout(ctx, 6*time.Second)
		st, statusErr := lc.Status(attemptCtx)
		var peer *ipnstate.PeerStatus
		var ip netip.Addr
		err = statusErr
		if err == nil && st.Self == nil {
			err = errors.New("missing own identity")
		}
		if err == nil {
			f["self_relay"] = st.Self.Relay
			peer, err = findPeer(st, *peerName)
		}
		if err == nil {
			ip, err = peerIPv4(peer)
			f["peer_online"] = peer.Online
			f["peer_relay"] = peer.Relay
			f["peer_direct_address"] = peer.CurAddr
			f["peer_relay_address"] = peer.PeerRelay
			f["rx_bytes"] = peer.RxBytes
			f["tx_bytes"] = peer.TxBytes
		}
		if err == nil {
			allowed.Store(ip.String())
			if peer.CurAddr != "" || peer.PeerRelay != "" {
				err = errors.New("non-DERP peer path detected")
			}
		}
		if err == nil {
			hash, roundErr := roundTrip(attemptCtx, server, ip)
			err = roundErr
			if err == nil {
				f["sha256"] = hash
			}
		}
		// DISCO includes the actual DERP region, unlike cached status alone.
		if err == nil && sequence%5 == 0 {
			pingCtx, pingDone := context.WithTimeout(ctx, 3*time.Second)
			ping, pingErr := lc.Ping(pingCtx, ip, tailcfg.PingDisco)
			pingDone()
			if pingErr != nil {
				f["path_error"] = safeErr(pingErr)
			} else {
				f["path_derp_region_id"] = ping.DERPRegionID
				f["path_derp_region_code"] = ping.DERPRegionCode
				f["path_error"] = ping.Err
				if ping.Endpoint != "" || ping.PeerRelay != "" || ping.DERPRegionID == 0 {
					err = errors.New("DISCO did not confirm DERP path")
				}
			}
		}
		done()
		f["ok"] = err == nil
		f["error"] = safeErr(err)
		f["elapsed_ms"] = time.Since(start).Milliseconds()
		emit("probe", f)
	}
}
func main() {
	if err := run(); err != nil {
		emit("fatal", map[string]any{"error": safeErr(err)})
		os.Exit(1)
	}
}
