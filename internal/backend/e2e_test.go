package backend

import (
	"encoding/binary"
	"encoding/hex"
	"net"
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
}

func dial(t *testing.T, port int) *fakeClient {
	u, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
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

// call sends an RMC request and returns the response, acking the server.
func (f *fakeClient) call(proto uint16, method uint32, body []byte) *rmc.Message {
	f.seq++
	f.send(&prudp.Packet{Type: prudp.TypeData, Flags: prudp.FlagNeedAck | prudp.FlagReliable, Signature: f.sig,
		Seq: f.seq, Payload: f.codec.Encode(rmc.Request(proto, 7, method, body))})
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

func TestLoginAndRegister(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The game sends hex(InitialHash(password)) when creating accounts.
	acct, err := store.Create("Racer", ParseKey(hex.EncodeToString(kerberos.InitialHash([]byte("hunter2")))), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	settings := &prudp.Settings{AccessKey: "3wyEgW4x"}
	b := New(Config{PublicIP: "127.0.0.1", AuthPort: 39120, SecurePort: 39121, GuestSecret: "x"}, store, settings)
	go b.Auth.ListenAndServe("127.0.0.1:39120")
	go b.Secure.ListenAndServe("127.0.0.1:39121")
	time.Sleep(100 * time.Millisecond)

	// Unknown user is rejected.
	auth := dial(t, 39120)
	auth.connect(nil)
	w := &rmc.Writer{}
	w.String("nobody")
	if m := auth.call(ProtoTicketGranting, 1, w.Bytes()); !m.OK || rmc.NewReader(m.Body).U32() != rmc.ErrRVInvalidUsername {
		t.Fatalf("expected InvalidUsername retval, got ok=%v err=%08x body=%x", m.OK, m.Error, m.Body)
	}

	// Real login.
	w = &rmc.Writer{}
	w.String("Racer")
	m := auth.call(ProtoTicketGranting, 1, w.Bytes())
	if !m.OK || m.Method != 1 {
		t.Fatalf("login failed: %+v", m)
	}
	r := rmc.NewReader(m.Body)
	if r.U32() != rmc.ResultSuccess {
		t.Fatal("bad result")
	}
	pid := r.U32()
	ticket := r.Buffer()
	url := r.String()
	if pid != acct.PID || url != b.SecureURL() || r.Err() != nil {
		t.Fatalf("pid=%d url=%q err=%v", pid, url, r.Err())
	}
	plain, err := kerberos.Decrypt(kerberos.DeriveKey([]byte("hunter2"), pid), ticket)
	if err != nil {
		t.Fatalf("ticket: %v", err)
	}
	tr := rmc.NewReader(plain)
	sessionKey := append([]byte(nil), plain[:16]...)
	tr.Rest()
	tr = rmc.NewReader(plain[16:])
	if tr.U32() != PIDSecureServer {
		t.Fatal("ticket target is not the secure server")
	}
	serverTicket := tr.Buffer()

	// Secure connection with the ticket.
	sec := dial(t, 39121)
	req := make([]byte, 12)
	binary.LittleEndian.PutUint32(req[0:], pid)
	binary.LittleEndian.PutUint32(req[4:], 1)
	binary.LittleEndian.PutUint32(req[8:], 0xCAFE)
	cw := &rmc.Writer{}
	cw.Buffer(serverTicket)
	cw.Buffer(kerberos.Encrypt(sessionKey, req))
	reply := sec.connect(cw.Bytes())
	rr := rmc.NewReader(reply)
	if got := binary.LittleEndian.Uint32(rr.Buffer()); got != 0xCAFF {
		t.Fatalf("response check = %x", got)
	}

	w = &rmc.Writer{}
	w.StringList([]string{"prudp:/address=192.168.1.2;port=3074;sid=15;type=2"})
	m = sec.call(ProtoSecureConnection, 1, w.Bytes())
	if !m.OK {
		t.Fatalf("register failed: %+v", m)
	}
	r = rmc.NewReader(m.Body)
	if r.U32() != rmc.ResultSuccess || r.U32() == 0 || r.String() == "" || r.Err() != nil {
		t.Fatal("bad register response")
	}

	// RegisterGathering body captured from the real game (private match).
	body, _ := hex.DecodeString("0f0041545647616d6553657373696f6e005a0000005600000000000000000000000000000002000800010000000000000000000000000000000c00537065656472756e6e657200020000000000000000000000000000000000000000000000010000000000000000000000efbeadde")
	m = sec.call(ProtoMatchMaking, 1, body)
	if !m.OK {
		t.Fatalf("RegisterGathering failed: %+v", m)
	}
	gid := rmc.NewReader(m.Body).U32()
	if gid == 0 {
		t.Fatal("gathering id 0")
	}
	w = &rmc.Writer{}
	w.String("ATVGameSession")
	w.U32(0)
	w.U32(10)
	m = sec.call(ProtoMatchMaking, 17, w.Bytes())
	r = rmc.NewReader(m.Body)
	if n := r.U32(); n != 1 {
		t.Fatalf("FindByType returned %d gatherings", n)
	}
	typ, data := readAnyData(r)
	if typ != "ATVGameSession" || binary.LittleEndian.Uint32(data) != gid ||
		binary.LittleEndian.Uint32(data[4:]) != pid || parseDescription(data) != "Speedrunner" || len(data) != 86 {
		t.Fatalf("bad gathering %q %x", typ, data)
	}
}
