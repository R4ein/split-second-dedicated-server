package backend

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
)

// Station URLs look like "prudp:/address=192.168.0.16;port=9103;sid=15".
// The game registers the addresses of all its network adapters (home LAN,
// virtual LANs such as Radmin/ZeroTier/Tailscale, Docker bridges...), so the
// server adds the public address it sees each player connect from and
// orders the list for each peer. The game only connects directly (its
// routing mode is compiled out), trying URLs in order with a timeout each,
// so unreachable entries are dropped rather than just ranked low.

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

// Address ranges of common virtual-LAN tools. Two players with addresses in
// the same range can reach each other directly through that tool.
var overlayNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"26.0.0.0/8",    // Radmin VPN
		"25.0.0.0/8",    // LogMeIn Hamachi
		"100.64.0.0/10", // Tailscale (and carrier-grade NAT)
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func urlIP(u string) net.IP { return net.ParseIP(urlParams(u)["address"]).To4() }

// netRank says how likely a LAN address of the target is reachable from a
// requester with the given local addresses: 2 = same virtual LAN, 1 = same
// /24 private subnet, 0 = not shared, -1 = useless (link-local, or an
// address the requester itself has).
func netRank(ip net.IP, mine []net.IP) int {
	if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsUnspecified() {
		return -1
	}
	rank := 0
	for _, m := range mine {
		if m.Equal(ip) {
			return -1
		}
		for _, n := range overlayNets {
			if n.Contains(ip) && n.Contains(m) {
				rank = 2
			}
		}
		if rank < 1 && ip[0] == m[0] && ip[1] == m[1] && ip[2] == m[2] {
			rank = 1
		}
	}
	return rank
}

// stationURLs returns the URLs requester should use to reach target:
//
//  1. addresses on a virtual LAN both players are on
//  2. same public IP (same household, or the same VPN exit): shared-subnet
//     LAN addresses, then public addresses, then the other LAN addresses
//  3. different public IPs: public addresses (NAT mapping, then public IP
//     with the game port for forwarded routers), then shared-subnet LAN
//     addresses; other LAN addresses are unreachable and dropped
func stationURLs(target, requester *prudp.Conn) []string {
	pub := []string{publicURL(target)}
	for _, u := range registeredURLs(target) {
		if p := urlParams(u)["port"]; p != "" && p != strconv.Itoa(target.Addr.Port) {
			alt := fmt.Sprintf("prudp:/address=%s;port=%s;sid=15;type=3", target.Addr.IP, p)
			if !contains(pub, alt) {
				pub = append(pub, alt)
			}
		}
	}
	var mine []net.IP
	if requester != nil {
		for _, u := range registeredURLs(requester) {
			if ip := urlIP(u); ip != nil {
				mine = append(mine, ip)
			}
		}
	}
	var overlay, shared, other []string
	for _, u := range registeredURLs(target) {
		switch netRank(urlIP(u), mine) {
		case 2:
			overlay = append(overlay, u)
		case 1:
			shared = append(shared, u)
		case 0:
			other = append(other, u)
		}
	}
	out := append([]string(nil), overlay...)
	if sameNetwork(target, requester) {
		out = append(out, shared...)
		out = append(out, pub...)
		return append(out, other...)
	}
	out = append(out, pub...)
	return append(out, shared...)
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
