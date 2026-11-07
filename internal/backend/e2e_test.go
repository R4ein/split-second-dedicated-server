package backend

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/R4ein/split-second-dedicated-server/internal/kerberos"
	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// fakeClient speaks just enough PRUDP v0 to drive the server like the game.
type fakeClient struct {
	t       *testing.T
	udp     *net.UDPConn
	codec   prudp.Codec
	keySum  byte
	sig     uint32 // server's signature
	mySig   uint32
	seq     uint16
	session uint8
	callID  uint32
}

func dial(t *testing.T, port int) *fakeClient {
	u, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return &fakeClient{t: t, udp: u, codec: prudp.Codec{RC4Key: []byte("CD&ML"), Compression: true},
		keySum: prudp.KeySum("3wyEgW4x"), mySig: 0x11223344, session: 0x5a}
}

func (f *fakeClient) send(p *prudp.Packet) {
	p.Src, p.Dst, p.Session = 0x3f, 0x31, f.session
	if _, err := f.udp.Write(p.Encode(prudp.Layout3x5, f.keySum)); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeClient) recv() *prudp.Packet {
	buf := make([]byte, 4096)
	f.udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := f.udp.Read(buf)
	if err != nil {
		f.t.Fatalf("recv: %v", err)
	}
	p, err := prudp.Decode(buf[:n], prudp.Layout3x5)
	if err != nil {
		f.t.Fatal(err)
	}
	if prudp.Checksum(buf[:n-1], f.keySum) != buf[n-1] {
		f.t.Fatal("bad checksum from server")
	}
	return p
}

func (f *fakeClient) connect(payload []byte) []byte {
	f.send(&prudp.Packet{Type: prudp.TypeSyn, Flags: prudp.FlagNeedAck})
	syn := f.recv()
	if syn.Type != prudp.TypeSyn || syn.Flags&prudp.FlagAck == 0 {
		f.t.Fatalf("expected SYN-ACK, got %s", syn)
	}
	f.sig = syn.ConnSig
	f.seq = 1
	f.send(&prudp.Packet{Type: prudp.TypeConnect, Flags: prudp.FlagNeedAck | prudp.FlagReliable, Signature: f.sig,
		Seq: f.seq, ConnSig: f.mySig, Payload: f.codec.Encode(payload)})
	ack := f.recv()
	if ack.Type != prudp.TypeConnect || ack.Signature != f.mySig {
		f.t.Fatalf("bad CONNECT ack %s", ack)
	}
	d, err := f.codec.Decode(ack.Payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

// next returns the next RMC message from the server, acking it.
func (f *fakeClient) next() *rmc.Message {
	for {
		p := f.recv()
		if p.Flags&prudp.FlagAck != 0 {
			continue
		}
		f.send(&prudp.Packet{Type: prudp.TypeData, Flags: prudp.FlagAck, Signature: f.sig, Seq: p.Seq})
		d, err := f.codec.Decode(p.Payload)
		if err != nil {
			f.t.Fatal(err)
		}
		m, err := rmc.Parse(d)
		if err != nil {
			f.t.Fatal(err)
		}
		return m
	}
}

// call sends an RMC request and returns the response.
func (f *fakeClient) call(proto uint16, method uint32, body []byte) *rmc.Message {
	f.seq++
	f.callID++
	f.send(&prudp.Packet{Type: prudp.TypeData, Flags: prudp.FlagNeedAck | prudp.FlagReliable, Signature: f.sig,
		Seq: f.seq, Payload: f.codec.Encode(rmc.Request(proto, f.callID, method, body))})
	m := f.next()
	if m.Request || m.CallID != f.callID {
		f.t.Fatalf("expected response to call %d, got %+v", f.callID, m)
	}
	return m
}

type testServer struct {
	b              *Backend
	authPort, secP int
}

var nextTestPort = 39120

func startServer(t *testing.T) *testServer {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ap, sp := nextTestPort, nextTestPort+1
	nextTestPort += 2
	settings := &prudp.Settings{AccessKey: "3wyEgW4x"}
	b := New(Config{PublicIP: "127.0.0.1", AuthPort: ap, SecurePort: sp, GuestSecret: "h7fyctiuucf"}, store, settings)
	go b.Auth.ListenAndServe(net.JoinHostPort("127.0.0.1", strconv.Itoa(ap)))
	go b.Secure.ListenAndServe(net.JoinHostPort("127.0.0.1", strconv.Itoa(sp)))
	time.Sleep(100 * time.Millisecond)
	return &testServer{b: b, authPort: ap, secP: sp}
}

func str(s string) []byte {
	w := &rmc.Writer{}
	w.String(s)
	return w.Bytes()
}

// login creates (if needed) and logs in an account, connects to the secure
// server and registers lanURL. It returns the secure connection and pid.
func (s *testServer) login(t *testing.T, name, password, lanURL string) (*fakeClient, uint32) {
	if s.b.Store.ByName(name) == nil {
		// The game sends hex(InitialHash(password)) when creating accounts.
		if _, err := s.b.Store.Create(name, ParseKey(hex.EncodeToString(kerberos.InitialHash([]byte(password)))), "", 0); err != nil {
			t.Fatal(err)
		}
	}
	auth := dial(t, s.authPort)
	auth.connect(nil)
	m := auth.call(ProtoTicketGranting, 1, str(name))
	r := rmc.NewReader(m.Body)
	if !m.OK || r.U32() != rmc.ResultSuccess {
		t.Fatalf("login %s failed: %+v", name, m)
	}
	pid := r.U32()
	ticket := r.Buffer()
	if url := r.String(); url != s.b.SecureURL() || r.Err() != nil {
		t.Fatalf("secure url %q err %v", url, r.Err())
	}
	plain, err := kerberos.Decrypt(kerberos.DeriveKey([]byte(password), pid), ticket)
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	sessionKey := append([]byte(nil), plain[:16]...)
	tr := rmc.NewReader(plain[16:])
	if tr.U32() != PIDSecureServer {
		t.Fatal("ticket target is not the secure server")
	}
	serverTicket := tr.Buffer()

	sec := dial(t, s.secP)
	req := make([]byte, 12)
	binary.LittleEndian.PutUint32(req[0:], pid)
	binary.LittleEndian.PutUint32(req[8:], 0xCAFE)
	cw := &rmc.Writer{}
	cw.Buffer(serverTicket)
	cw.Buffer(kerberos.Encrypt(sessionKey, req))
	if got := binary.LittleEndian.Uint32(rmc.NewReader(sec.connect(cw.Bytes())).Buffer()); got != 0xCAFF {
		t.Fatalf("response check = %x", got)
	}
	w := &rmc.Writer{}
	w.StringList([]string{lanURL})
	m = sec.call(ProtoSecureConnection, 1, w.Bytes())
	r = rmc.NewReader(m.Body)
	if !m.OK || r.U32() != rmc.ResultSuccess || r.U32() == 0 || !strings.HasPrefix(r.String(), "prudp:/address=127.0.0.1;port=") {
		t.Fatalf("register failed: %+v", m)
	}
	return sec, pid
}

func TestLoginAndRegister(t *testing.T) {
	s := startServer(t)

	// Unknown user: qResult InvalidUsername inside a successful response.
	auth := dial(t, s.authPort)
	auth.connect(nil)
	if m := auth.call(ProtoTicketGranting, 1, str("nobody")); !m.OK || rmc.NewReader(m.Body).U32() != rmc.ErrRVInvalidUsername {
		t.Fatalf("expected InvalidUsername retval, got ok=%v err=%08x body=%x", m.OK, m.Error, m.Body)
	}

	sec, pid := s.login(t, "Racer", "hunter2", "prudp:/address=192.168.1.2;port=3074;sid=15")

	// RegisterGathering body captured from the real game (private match).
	body, _ := hex.DecodeString("0f0041545647616d6553657373696f6e005a0000005600000000000000000000000000000002000800010000000000000000000000000000000c00537065656472756e6e657200020000000000000000000000000000000000000000000000010000000000000000000000efbeadde")
	m := sec.call(ProtoMatchMaking, 1, body)
	if !m.OK {
		t.Fatalf("RegisterGathering failed: %+v", m)
	}
	gid := rmc.NewReader(m.Body).U32()
	w := &rmc.Writer{}
	w.String("ATVGameSession")
	w.U32(0)
	w.U32(10)
	m = sec.call(ProtoMatchMaking, 17, w.Bytes())
	r := rmc.NewReader(m.Body)
	if n := r.U32(); n != 1 {
		t.Fatalf("FindByType returned %d gatherings", n)
	}
	typ, data := readAnyData(r)
	if typ != "ATVGameSession" || binary.LittleEndian.Uint32(data) != gid ||
		binary.LittleEndian.Uint32(data[4:]) != pid || parseDescription(data) != "Speedrunner" || len(data) != 86 {
		t.Fatalf("bad gathering %q %x", typ, data)
	}
}

// Host creates a lobby, invites a guest by name, the guest accepts, gets
// the host's URLs and asks the server to set up NAT hole punching.
func TestInviteJoinAndNAT(t *testing.T) {
	s := startServer(t)
	host, hostPID := s.login(t, "Host", "pw1", "prudp:/address=192.168.0.16;port=9103;sid=15")
	guest, guestPID := s.login(t, "Visitor", "pw2", "prudp:/address=192.168.0.18;port=9103;sid=15")

	body, _ := hex.DecodeString("0f0041545647616d6553657373696f6e005a0000005600000000000000000000000000000002000800010000000000000000000000000000000c00537065656472756e6e657200020000000000000000000000000000000000000000000000010000000000000000000000efbeadde")
	gid := rmc.NewReader(host.call(ProtoMatchMaking, 1, body).Body).U32()

	// INVITE slot: GetPID on the secure connection, then GetStatus.
	m := host.call(ProtoTicketGranting, 4, str("visitor"))
	if !m.OK || rmc.NewReader(m.Body).U32() != guestPID {
		t.Fatalf("GetPID on secure: %+v", m)
	}
	w := &rmc.Writer{}
	w.U32(guestPID)
	if st := rmc.NewReader(host.call(ProtoAccountManagement, 18, w.Bytes()).Body).String(); st != "Online" {
		t.Fatalf("status %q", st)
	}
	// Login on the secure connection stays forbidden.
	if m := host.call(ProtoTicketGranting, 1, str("Visitor")); m.OK {
		t.Fatal("Login accepted on the secure server")
	}

	w = &rmc.Writer{}
	w.U32(gid)
	w.U32List([]uint32{guestPID})
	w.String("join me")
	if !rmc.NewReader(host.call(ProtoMatchMaking, 5, w.Bytes()).Body).Bool() {
		t.Fatal("Invite failed")
	}

	r := rmc.NewReader(guest.call(ProtoMatchMaking, 10, nil).Body)
	if n := r.U32(); n != 1 || r.U32() != gid || r.U32() != guestPID || r.String() != "join me" || r.Err() != nil {
		t.Fatal("GetInvitationsReceived did not return the invitation")
	}
	w = &rmc.Writer{}
	w.U32(gid)
	w.String("")
	if !rmc.NewReader(guest.call(ProtoMatchMaking, 6, w.Bytes()).Body).Bool() {
		t.Fatal("AcceptInvitation failed")
	}
	if n := rmc.NewReader(guest.call(ProtoMatchMaking, 10, nil).Body).U32(); n != 0 {
		t.Fatal("invitation not removed after accepting")
	}
	// Like the real game, the guest does not call Participate after
	// accepting: accepting must have made it a participant.
	w = &rmc.Writer{}
	w.U32(gid)
	if parts := rmc.NewReader(guest.call(ProtoMatchMaking, 13, w.Bytes()).Body).U32List(); !containsPID(parts, guestPID) {
		t.Fatalf("guest not a participant after accepting: %v", parts)
	}

	// Friends.AddFriend (sent by the game when inviting) succeeds.
	w = &rmc.Writer{}
	w.U32(guestPID)
	w.U32(0)
	w.String("")
	if !rmc.NewReader(host.call(ProtoFriends, 1, w.Bytes()).Body).Bool() {
		t.Fatal("AddFriend failed")
	}

	// Same public IP (127.0.0.1) for both, so LAN URLs come first; the
	// guest's own URLs are excluded.
	w = &rmc.Writer{}
	w.U32(gid)
	urls := rmc.NewReader(guest.call(ProtoMatchMaking, 16, w.Bytes()).Body).StringList()
	if len(urls) < 2 || urls[0] != "prudp:/address=192.168.0.16;port=9103;sid=15" || !strings.HasPrefix(urls[1], "prudp:/address=127.0.0.1;") {
		t.Fatalf("participant URLs %v", urls)
	}
	for _, u := range urls {
		if strings.Contains(u, "192.168.0.18") {
			t.Fatalf("guest got its own URL: %v", urls)
		}
	}

	// Hole punching via the host's public URL: the host must be asked to
	// probe the guest.
	w = &rmc.Writer{}
	w.StringList([]string{urls[1]})
	if m := guest.call(ProtoNATTraversal, 1, w.Bytes()); !m.OK {
		t.Fatalf("RequestProbeInitiation: %+v", m)
	}
	probe := host.next()
	if !probe.Request || probe.Proto != ProtoNATTraversal || probe.Method != natInitiateProbe {
		t.Fatalf("host got %+v, want InitiateProbe", probe)
	}
	toProbe := rmc.NewReader(probe.Body).String()
	if !strings.HasPrefix(toProbe, "prudp:/address=127.0.0.1;port=") || !strings.Contains(toProbe, "sid=15") {
		t.Fatalf("InitiateProbe URL %q", toProbe)
	}

	// Via the LAN URL too (same network).
	w = &rmc.Writer{}
	w.StringList([]string{urls[0]})
	guest.call(ProtoNATTraversal, 1, w.Bytes())
	if m := host.next(); m.Method != natInitiateProbe {
		t.Fatalf("no probe for LAN URL: %+v", m)
	}
	_ = hostPID
}
