package prudp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Settings are shared by every PRUDP server in the process. Layout and
// codec are detected from the first packets the game sends and logged.
type Settings struct {
	AccessKey string
	Verbose   bool

	mu          sync.Mutex
	layout      Layout
	codec       Codec
	codecKnown  bool
	csumWarned  bool
	ForceCodec  *Codec
	ForceLayout Layout
}

func (s *Settings) Layout() Layout {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.layout
}

func (s *Settings) Codec() (Codec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ForceCodec != nil {
		return *s.ForceCodec, true
	}
	return s.codec, s.codecKnown
}

func (s *Settings) detectLayout(b byte) Layout {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ForceLayout != LayoutUnknown {
		s.layout = s.ForceLayout
	}
	if s.layout != LayoutUnknown {
		return s.layout
	}
	switch b {
	case 0x20: // SYN | NEED_ACK in 3/5 layout
		s.layout = Layout3x5
	case 0x40: // SYN | NEED_ACK in 4/4 layout
		s.layout = Layout4x4
	default:
		return Layout3x5
	}
	log.Printf("[prudp] detected type/flags layout: %s (first byte 0x%02x)", s.layout, b)
	return s.layout
}

// Handler receives connection events. All calls are made with the server
// lock held, so handlers must not block.
type Handler interface {
	// OnConnect gets the decoded CONNECT payload (may be empty) and returns
	// the payload for the CONNECT ack, or an error to refuse the connection.
	OnConnect(c *Conn, payload []byte) ([]byte, error)
	// OnMessage gets one complete, reassembled, decoded DATA message.
	OnMessage(c *Conn, msg []byte)
	OnDisconnect(c *Conn)
}

type Server struct {
	Name     string
	Settings *Settings
	Handler  Handler

	udp   *net.UDPConn
	mu    sync.Mutex
	conns map[string]*Conn
}

type pending struct {
	raw   []byte
	last  time.Time
	tries int
}

// Conn is one PRUDP connection from a game client.
type Conn struct {
	srv       *Server
	Addr      *net.UDPAddr
	local     uint8
	remote    uint8
	session   uint8
	serverSig uint32
	clientSig uint32
	hasSize   bool
	connected bool

	recvInit bool
	recvNext uint16
	recvBuf  map[uint16]*Packet
	frags    []byte

	sendNext      uint16
	pending       map[uint16]*pending
	lastSeen      time.Time
	codecOverride *Codec
	connectAck    []byte

	// Application state, owned by the Handler.
	PID        uint32
	User       string
	SessionKey []byte
	CID        uint32
	Data       map[string]any
}

func (s *Server) ListenAndServe(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	s.udp, err = net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	s.conns = map[string]*Conn{}
	log.Printf("[%s] listening on udp %s", s.Name, s.udp.LocalAddr())
	go s.retransmitLoop()
	buf := make([]byte, 65536)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[%s] read: %v", s.Name, err)
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		s.mu.Lock()
		s.handle(from, data)
		s.mu.Unlock()
	}
}

func (s *Server) logf(format string, a ...any) {
	log.Printf("["+s.Name+"] "+format, a...)
}

func (s *Server) handle(from *net.UDPAddr, data []byte) {
	if len(data) < 11 {
		s.logf("%s: runt datagram %x", from, data)
		return
	}
	layout := s.Settings.detectLayout(data[2])
	p, err := Decode(data, layout)
	if err != nil {
		s.logf("%s: bad packet (%v): %x", from, err, data)
		return
	}
	keySum := KeySum(s.Settings.AccessKey)
	if want := Checksum(data[:len(data)-1], keySum); want != p.Checksum {
		s.Settings.mu.Lock()
		warn := !s.Settings.csumWarned
		s.Settings.csumWarned = true
		s.Settings.mu.Unlock()
		if warn {
			s.logf("checksum mismatch from %s: got %02x want %02x (access key %q). Accepting anyway; raw=%x", from, p.Checksum, want, s.Settings.AccessKey, data)
		}
	}
	if s.Settings.Verbose {
		s.logf("<- %s %s", from, p)
	}

	key := from.String()
	c := s.conns[key]
	if p.Type == TypeSyn {
		if p.Flags&FlagAck != 0 {
			return
		}
		if c != nil && c.connected {
			c.close("reconnect (new SYN)")
		}
		c = &Conn{
			srv: s, Addr: from, local: p.Dst, remote: p.Src, session: p.Session,
			serverSig: randU32(), hasSize: p.Flags&FlagHasSize != 0,
			recvBuf: map[uint16]*Packet{}, sendNext: 1, pending: map[uint16]*pending{},
			Data: map[string]any{},
		}
		s.conns[key] = c
		c.lastSeen = time.Now()
		c.write(&Packet{Src: c.local, Dst: c.remote, Type: TypeSyn, Flags: FlagAck | c.sizeFlag(), Session: p.Session,
			Signature: p.Signature, Seq: p.Seq, ConnSig: c.serverSig})
		return
	}
	if c == nil {
		s.logf("%s: %s from unknown connection, ignoring", from, p.Type)
		return
	}
	c.lastSeen = time.Now()

	switch p.Type {
	case TypeConnect:
		if p.Flags&FlagAck != 0 {
			return
		}
		if c.connected && p.ConnSig == c.clientSig && c.connectAck != nil {
			// Retransmitted CONNECT (our ack was lost or slow): resend it.
			s.udp.WriteToUDP(c.connectAck, c.Addr)
			return
		}
		c.clientSig = p.ConnSig
		c.session = p.Session
		var reply []byte
		if len(p.Payload) > 0 {
			codec, ok := s.Settings.Codec()
			if !ok {
				codec = Codec{RC4Key: []byte("CD&ML"), Compression: true}
			}
			dec, err := codec.Decode(p.Payload)
			if err != nil {
				s.logf("%s: CONNECT payload decode (%s): %v raw=%x", from, codec, err, p.Payload)
				dec = p.Payload
			}
			if s.Settings.Verbose {
				s.logf("   CONNECT payload raw=%x decoded=%x", p.Payload, dec)
			}
			r, err := s.Handler.OnConnect(c, dec)
			if err != nil {
				s.logf("%s: CONNECT refused: %v", from, err)
				return
			}
			reply = r
		} else if _, err := s.Handler.OnConnect(c, nil); err != nil {
			s.logf("%s: CONNECT refused: %v", from, err)
			return
		}
		var payload []byte
		if len(reply) > 0 {
			codec, _ := s.Settings.Codec()
			payload = codec.Encode(reply)
		}
		c.connected = true
		c.connectAck = c.write(&Packet{Src: c.local, Dst: c.remote, Type: TypeConnect, Flags: FlagAck | c.sizeFlag(), Session: c.session,
			Signature: c.clientSig, Seq: p.Seq, ConnSig: c.serverSig, Payload: payload})
		s.logf("%s connected (client sig %08x, server sig %08x)", from, c.clientSig, c.serverSig)

	case TypeData:
		if p.Flags&FlagAck != 0 {
			delete(c.pending, p.Seq)
			return
		}
		if p.Flags&FlagNeedAck != 0 {
			c.ack(p)
		}
		if p.Flags&FlagReliable == 0 {
			c.receive(p)
			return
		}
		if !c.recvInit {
			c.recvInit, c.recvNext = true, p.Seq
		}
		if int16(p.Seq-c.recvNext) < 0 {
			return // duplicate, already acked again above
		}
		c.recvBuf[p.Seq] = p
		for {
			q, ok := c.recvBuf[c.recvNext]
			if !ok {
				break
			}
			delete(c.recvBuf, c.recvNext)
			c.recvNext++
			c.receive(q)
		}

	case TypePing:
		if p.Flags&FlagAck != 0 {
			return
		}
		if p.Flags&FlagNeedAck != 0 {
			c.ack(p)
		}

	case TypeDisconnect:
		if p.Flags&FlagAck != 0 {
			return
		}
		for i := 0; i < 3; i++ {
			c.ack(p)
		}
		c.close("client disconnected")

	default:
		s.logf("%s: unhandled packet %s payload=%x", from, p, p.Payload)
	}
}

func (c *Conn) sizeFlag() uint8 {
	if c.hasSize {
		return FlagHasSize
	}
	return 0
}

func (c *Conn) ack(p *Packet) {
	c.write(&Packet{Src: c.local, Dst: c.remote, Type: p.Type, Flags: FlagAck | c.sizeFlag(), Session: c.session,
		Signature: c.clientSig, Seq: p.Seq, Fragment: p.Fragment})
}

func (c *Conn) codec() (Codec, bool) {
	if c.codecOverride != nil {
		return *c.codecOverride, true
	}
	return c.srv.Settings.Codec()
}

func (c *Conn) receive(p *Packet) {
	s := c.srv
	codec, known := c.codec()
	single := len(c.frags) == 0 && p.Fragment == 0
	if known && single && c.codecOverride == nil && c.SessionKey != nil {
		// Secure connections may switch to the Kerberos session key.
		if d, err := codec.Decode(p.Payload); err != nil || !LooksLikeRMC(d) {
			for _, comp := range []bool{codec.Compression, !codec.Compression} {
				alt := Codec{RC4Key: c.SessionKey, Compression: comp}
				if d, err := alt.Decode(p.Payload); err == nil && LooksLikeRMC(d) {
					c.codecOverride = &alt
					codec = alt
					s.logf("%s: payloads use the session key: %s", c.Addr, alt)
					break
				}
			}
		}
	}
	if !known && single {
		if det, ok := DetectCodec(p.Payload); ok {
			s.Settings.mu.Lock()
			s.Settings.codec, s.Settings.codecKnown = det, true
			s.Settings.mu.Unlock()
			codec = det
			s.logf("detected payload encoding: %s", det)
		} else {
			s.logf("could not detect payload encoding; raw payload=%x", p.Payload)
		}
	}
	dec, err := codec.Decode(p.Payload)
	if err != nil {
		s.logf("%s: payload decode failed (%v), raw=%x", c.Addr, err, p.Payload)
		return
	}
	c.frags = append(c.frags, dec...)
	if p.Fragment != 0 {
		return
	}
	msg := c.frags
	c.frags = nil
	if s.Settings.Verbose {
		s.logf("<- %s message %s", c.Addr, dump(msg))
	}
	s.Handler.OnMessage(c, msg)
}

const maxFragment = 900

// Send queues a reliable message to the client, fragmenting as needed.
func (c *Conn) Send(msg []byte) {
	if c.srv.Settings.Verbose {
		c.srv.logf("-> %s message %s", c.Addr, dump(msg))
	}
	codec, _ := c.codec()
	for off := 0; off < len(msg); off += maxFragment {
		end := min(off+maxFragment, len(msg))
		frag := uint8(off/maxFragment + 1)
		if end == len(msg) {
			frag = 0
		}
		p := &Packet{Src: c.local, Dst: c.remote, Type: TypeData, Flags: FlagReliable | FlagNeedAck | c.sizeFlag(),
			Session: c.session, Signature: c.clientSig, Seq: c.sendNext, Fragment: frag, Payload: codec.Encode(msg[off:end])}
		c.sendNext++
		raw := c.write(p)
		c.pending[p.Seq] = &pending{raw: raw, last: time.Now()}
	}
}

func (c *Conn) write(p *Packet) []byte {
	s := c.srv
	raw := p.Encode(s.Settings.Layout(), KeySum(s.Settings.AccessKey))
	if s.Settings.Verbose {
		s.logf("-> %s %s", c.Addr, p)
	}
	if _, err := s.udp.WriteToUDP(raw, c.Addr); err != nil {
		s.logf("write %s: %v", c.Addr, err)
	}
	return raw
}

func (c *Conn) close(reason string) {
	s := c.srv
	if s.conns[c.Addr.String()] == c {
		delete(s.conns, c.Addr.String())
	}
	if c.connected { // half-open probes (e.g. health checks) close silently
		s.logf("%s closed: %s", c.Addr, reason)
	}
	s.Handler.OnDisconnect(c)
}

// Conns returns a snapshot of live connections. Call with no lock held.
func (s *Server) Conns() []*Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Conn, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, c)
	}
	return out
}

// Do runs f with the server lock held, for sending from outside a handler.
func (s *Server) Do(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

func (s *Server) retransmitLoop() {
	t := time.NewTicker(250 * time.Millisecond)
	for range t.C {
		s.mu.Lock()
		now := time.Now()
		for _, c := range s.conns {
			for seq, p := range c.pending {
				if now.Sub(p.last) < time.Second {
					continue
				}
				p.tries++
				if p.tries > 15 {
					delete(c.pending, seq)
					continue
				}
				p.last = now
				s.udp.WriteToUDP(p.raw, c.Addr)
			}
			if now.Sub(c.lastSeen) > 60*time.Second {
				c.close("timeout")
			}
		}
		s.mu.Unlock()
	}
}

func randU32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func dump(b []byte) string {
	if len(b) > 1024 {
		return fmt.Sprintf("(%d bytes) %s...", len(b), hex.EncodeToString(b[:1024]))
	}
	return fmt.Sprintf("(%d bytes) %s", len(b), hex.EncodeToString(b))
}
