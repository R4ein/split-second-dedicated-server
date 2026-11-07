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

func TestStationURLOrder(t *testing.T) {
	host := conn("95.177.109.138", 57987, "prudp:/address=192.168.0.18;port=9103;sid=15")

	// Different networks: public NAT mapping, then public IP + game port, then LAN.
	got := stationURLs(host, conn("212.11.29.129", 54680))
	want := []string{
		"prudp:/address=95.177.109.138;port=57987;sid=15;type=3",
		"prudp:/address=95.177.109.138;port=9103;sid=15;type=3",
		"prudp:/address=192.168.0.18;port=9103;sid=15",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remote order\n got %v\nwant %v", got, want)
	}

	// Same public IP: LAN first.
	got = stationURLs(host, conn("95.177.109.138", 11952))
	if got[0] != "prudp:/address=192.168.0.18;port=9103;sid=15" {
		t.Fatalf("same-LAN order %v", got)
	}
}

func TestURLParams(t *testing.T) {
	p := urlParams("prudps:/address=1.2.3.4;port=31121;CID=1;PID=2;sid=1;stream=3;type=2")
	if p["address"] != "1.2.3.4" || p["port"] != "31121" || p["pid"] != "2" || p["type"] != "2" {
		t.Fatalf("%v", p)
	}
}
