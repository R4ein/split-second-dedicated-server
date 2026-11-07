package backend

import (
	"net"
	"reflect"
	"testing"

	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
)

func conn(ip string, port int, lan ...string) *prudp.Conn {
	return &prudp.Conn{Addr: &net.UDPAddr{IP: net.ParseIP(ip), Port: port}, Data: map[string]any{"urls": lan}}
}

const (
	hostLAN    = "prudp:/address=192.168.0.18;port=9103;sid=15"
	hostRadmin = "prudp:/address=26.10.20.30;port=9103;sid=15"
	hostDocker = "prudp:/address=172.18.0.1;port=9103;sid=15"
	hostLink   = "prudp:/address=169.254.108.164;port=9103;sid=15"
	hostPub    = "prudp:/address=95.177.109.138;port=57987;sid=15;type=3"
	hostPub9   = "prudp:/address=95.177.109.138;port=9103;sid=15;type=3"
)

func TestStationURLOrder(t *testing.T) {
	host := conn("95.177.109.138", 57987, hostLAN, hostDocker, hostLink)

	// Different networks, nothing shared: public addresses only.
	got := stationURLs(host, conn("212.11.29.129", 54680, "prudp:/address=10.0.0.5;port=9103;sid=15"))
	if want := []string{hostPub, hostPub9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remote\n got %v\nwant %v", got, want)
	}

	// Same public IP (same home or same VPN exit): shared subnet, public,
	// then other LAN; the requester's own Docker address and link-local
	// addresses are dropped.
	got = stationURLs(host, conn("95.177.109.138", 11952,
		"prudp:/address=192.168.0.16;port=9103;sid=15", "prudp:/address=172.18.0.1;port=9103;sid=15"))
	if want := []string{hostLAN, hostPub, hostPub9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("same network\n got %v\nwant %v", got, want)
	}
}

// Two VPN users on the same exit IP who also joined a Radmin VPN network:
// the Radmin address must come first.
func TestStationURLVirtualLANFirst(t *testing.T) {
	host := conn("208.69.78.116", 16353, hostLAN, hostRadmin)
	got := stationURLs(host, conn("208.69.78.116", 63958,
		"prudp:/address=192.168.0.16;port=9103;sid=15", "prudp:/address=26.99.1.2;port=9103;sid=15"))
	if len(got) == 0 || got[0] != hostRadmin {
		t.Fatalf("virtual LAN not first: %v", got)
	}

	// Different public IPs: the shared virtual LAN still comes first.
	got = stationURLs(host, conn("212.11.29.129", 1, "prudp:/address=26.99.1.2;port=9103;sid=15"))
	if want := []string{hostRadmin, "prudp:/address=208.69.78.116;port=16353;sid=15;type=3", "prudp:/address=208.69.78.116;port=9103;sid=15;type=3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remote with radmin\n got %v\nwant %v", got, want)
	}
}

func TestURLParams(t *testing.T) {
	p := urlParams("prudps:/address=1.2.3.4;port=31121;CID=1;PID=2;sid=1;stream=3;type=2")
	if p["address"] != "1.2.3.4" || p["port"] != "31121" || p["pid"] != "2" || p["type"] != "2" {
		t.Fatalf("%v", p)
	}
}
