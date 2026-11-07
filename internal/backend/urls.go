package backend

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
)

// Station URLs look like "prudp:/address=192.168.0.16;port=9103;sid=15".
// The game registers only its LAN addresses, so the server adds the public
// address it sees each player connect from. Peers try the URLs in order.

func urlParams(u string) map[string]string {
	out := map[string]string{}
	if i := strings.Index(u, ":/"); i >= 0 {
		u = u[i+2:]
	}
	for _, kv := range strings.Split(u, ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return out
}

// publicURL is the player's station as seen from the internet: the source
// address and port of their secure connection (their NAT mapping).
func publicURL(c *prudp.Conn) string {
	return fmt.Sprintf("prudp:/address=%s;port=%d;sid=15;type=3", c.Addr.IP, c.Addr.Port)
}

func registeredURLs(c *prudp.Conn) []string {
	u, _ := c.Data["urls"].([]string)
	return u
}

func sameNetwork(a, b *prudp.Conn) bool {
	return a != nil && b != nil && a.Addr.IP.Equal(b.Addr.IP)
}

// stationURLs returns the URLs other players should use to reach target.
// Players behind the same public IP (same LAN) get the LAN URLs first, since
// many routers cannot loop traffic back to their own public address.
func stationURLs(target, requester *prudp.Conn) []string {
	pub := []string{publicURL(target)}
	// The public IP with the game's local port helps players who forwarded
	// that port on their router.
	for _, u := range registeredURLs(target) {
		if p := urlParams(u)["port"]; p != "" && p != strconv.Itoa(target.Addr.Port) {
			alt := fmt.Sprintf("prudp:/address=%s;port=%s;sid=15;type=3", target.Addr.IP, p)
			if !contains(pub, alt) {
				pub = append(pub, alt)
			}
		}
	}
	lan := registeredURLs(target)
	if sameNetwork(target, requester) {
		return append(append([]string(nil), lan...), pub...)
	}
	return append(pub, lan...)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// urlsFor returns pid's station URLs as seen by requester.
func (b *Backend) urlsFor(pid uint32, requester *prudp.Conn) []string {
	b.mu.Lock()
	target := b.sessions[pid]
	b.mu.Unlock()
	if target == nil {
		return nil
	}
	return stationURLs(target, requester)
}

// sessionForURL finds the logged-in player a station URL points at, by
// public address or by one of their registered LAN URLs.
func (b *Backend) sessionForURL(u string, requester *prudp.Conn) *prudp.Conn {
	p := urlParams(u)
	ip := net.ParseIP(p["address"])
	port, _ := strconv.Atoi(p["port"])
	if ip == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.sessions { // exact NAT mapping
		if s.Addr.IP.Equal(ip) && s.Addr.Port == port {
			return s
		}
	}
	for _, s := range b.sessions { // public IP + forwarded game port
		if s.Addr.IP.Equal(ip) && hasPort(registeredURLs(s), port) && s != requester {
			return s
		}
	}
	// A LAN address is only meaningful next to the requester's own network.
	for _, s := range b.sessions {
		if !sameNetwork(s, requester) {
			continue
		}
		for _, r := range registeredURLs(s) {
			rp := urlParams(r)
			if rip := net.ParseIP(rp["address"]); rip != nil && rip.Equal(ip) && rp["port"] == p["port"] {
				return s
			}
		}
	}
	return nil
}

func hasPort(urls []string, port int) bool {
	for _, u := range urls {
		if urlParams(u)["port"] == strconv.Itoa(port) {
			return true
		}
	}
	return false
}
