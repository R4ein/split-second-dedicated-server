package backend

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/R4ein/split-second-dedicated-server/internal/kerberos"
	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// Protocol IDs used by Quazal Rendez-Vous.
const (
	ProtoNATTraversal       uint16 = 3
	ProtoTicketGranting     uint16 = 10
	ProtoSecureConnection   uint16 = 11
	ProtoNotificationEvents uint16 = 14
	ProtoFriends            uint16 = 20
	ProtoMatchMaking        uint16 = 21
	ProtoMessaging          uint16 = 23
	ProtoAccountManagement  uint16 = 25
)

var protoNames = map[uint16]string{
	3: "NATTraversal", 10: "TicketGranting", 11: "SecureConnection", 14: "NotificationEvents",
	20: "Friends", 21: "MatchMaking", 23: "Messaging", 24: "PersistentStore", 25: "AccountManagement",
	27: "MessageDelivery",
}

func protoName(p uint16) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return fmt.Sprintf("Proto%d", p)
}

type Config struct {
	PublicIP     string
	AuthPort     int
	SecurePort   int
	GuestSecret  string // password the game uses for the "guest" account
	EncryptCheck bool   // encrypt the secure CONNECT reply with the session key
	// LoginErrorsAsRMC sends login failures as RMC error responses instead
	// of a qResult return value.
	LoginErrorsAsRMC bool
}

// Ctx is passed to each RMC method handler.
type Ctx struct {
	B    *Backend
	Conn *prudp.Conn
	Msg  *rmc.Message
	R    *rmc.Reader
}

// Method handles one RMC call. It returns the response body, or a non-zero
// Quazal error code.
type Method func(c *Ctx) (*rmc.Writer, uint32)

type Backend struct {
	Cfg   Config
	Store *Store

	Auth   *prudp.Server
	Secure *prudp.Server

	mu         sync.Mutex
	nextCID    uint32
	sessions   map[uint32]*prudp.Conn // pid -> secure connection
	nextGID    uint32
	gatherings map[uint32]*gathering

	methods map[uint16]map[uint32]Method
	names   map[uint16]map[uint32]string
}

func New(cfg Config, store *Store, settings *prudp.Settings) *Backend {
	b := &Backend{Cfg: cfg, Store: store, nextCID: 1, sessions: map[uint32]*prudp.Conn{},
		gatherings: map[uint32]*gathering{},
		methods:    map[uint16]map[uint32]Method{}, names: map[uint16]map[uint32]string{}}
	b.Auth = &prudp.Server{Name: "auth", Settings: settings, Handler: &authHandler{b}}
	b.Secure = &prudp.Server{Name: "secure", Settings: settings, Handler: &secureHandler{b}}
	b.registerTicketGranting()
	b.registerSecureConnection()
	b.registerAccountManagement()
	b.registerFriends()
	b.registerMatchMaking()
	return b
}

func (b *Backend) register(proto uint16, method uint32, name string, f Method) {
	if b.methods[proto] == nil {
		b.methods[proto] = map[uint32]Method{}
		b.names[proto] = map[uint32]string{}
	}
	b.methods[proto][method] = f
	b.names[proto][method] = name
}

func (b *Backend) dispatch(server string, c *prudp.Conn, raw []byte, allowed func(uint16) bool) {
	m, err := rmc.Parse(raw)
	if err != nil {
		log.Printf("[%s] %s: bad RMC (%v): %x", server, c.Addr, err, raw)
		return
	}
	if !m.Request {
		log.Printf("[%s] %s: RMC response to call %d (%s ok=%v err=%08x) body=%x", server, c.Addr, m.CallID, protoName(m.Proto), m.OK, m.Error, m.Body)
		return
	}
	name := b.names[m.Proto][m.Method]
	if name == "" {
		name = fmt.Sprintf("method%d", m.Method)
	}
	f := b.methods[m.Proto][m.Method]
	if f == nil || !allowed(m.Proto) {
		log.Printf("[%s] %s: UNIMPLEMENTED %s.%s (call %d) body=%x", server, c.Addr, protoName(m.Proto), name, m.CallID, m.Body)
		c.Send(rmc.ErrorResponse(m.Proto, m.CallID, rmc.ErrCoreNotImplemented))
		return
	}
	who := c.User
	if who == "" {
		who = c.Addr.String()
	}
	log.Printf("[%s] %s: %s.%s (call %d)", server, who, protoName(m.Proto), name, m.CallID)
	ctx := &Ctx{B: b, Conn: c, Msg: m, R: rmc.NewReader(m.Body)}
	w, code := f(ctx)
	if code == 0 && ctx.R.Err() != nil {
		log.Printf("[%s]   request parse error: %v body=%x", server, ctx.R.Err(), m.Body)
		code = rmc.ErrCoreInvalidArg
	}
	if code != 0 {
		log.Printf("[%s]   -> error %08x", server, code)
		c.Send(rmc.ErrorResponse(m.Proto, m.CallID, code))
		return
	}
	var body []byte
	if w != nil {
		body = w.Bytes()
	}
	c.Send(rmc.Response(m.Proto, m.CallID, m.Method, body))
}

func (b *Backend) newCID() uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextCID++
	return b.nextCID
}

func (b *Backend) SecureURL() string {
	return fmt.Sprintf("prudps:/address=%s;port=%d;CID=1;PID=%d;sid=1;stream=3;type=2", b.Cfg.PublicIP, b.Cfg.SecurePort, PIDSecureServer)
}

// userKey returns the Kerberos key for a PID (accounts or guest).
func (b *Backend) userKey(pid uint32) []byte {
	if pid == PIDGuest {
		return kerberos.DeriveKey([]byte(b.Cfg.GuestSecret), PIDGuest)
	}
	if a := b.Store.ByPID(pid); a != nil {
		return a.KeyBytes()
	}
	return nil
}

// makeTicket builds the ticket a user presents to targetPID, encrypted
// with the user's key. The inner ticket is readable only by this server.
func (b *Backend) makeTicket(userPID, targetPID uint32) ([]byte, error) {
	ukey := b.userKey(userPID)
	if ukey == nil {
		return nil, fmt.Errorf("no key for pid %d", userPID)
	}
	sessionKey := make([]byte, 16)
	rand.Read(sessionKey)

	inner := &rmc.Writer{}
	inner.Write(sessionKey)
	inner.U32(userPID)
	inner.U64(uint64(time.Now().Add(24 * time.Hour).Unix()))
	serverTicket := kerberos.Encrypt(b.Store.ServerKey(), inner.Bytes())

	outer := &rmc.Writer{}
	outer.Write(sessionKey)
	outer.U32(targetPID)
	outer.Buffer(serverTicket)
	return kerberos.Encrypt(ukey, outer.Bytes()), nil
}

func (b *Backend) readServerTicket(t []byte) (sessionKey []byte, pid uint32, err error) {
	plain, err := kerberos.Decrypt(b.Store.ServerKey(), t)
	if err != nil {
		return nil, 0, err
	}
	if len(plain) < 28 {
		return nil, 0, fmt.Errorf("server ticket too short")
	}
	exp := int64(binary.LittleEndian.Uint64(plain[20:]))
	if time.Now().Unix() > exp {
		return nil, 0, fmt.Errorf("ticket expired")
	}
	return plain[:16], binary.LittleEndian.Uint32(plain[16:]), nil
}

// ---- auth server ----

type authHandler struct{ b *Backend }

func (h *authHandler) OnConnect(c *prudp.Conn, payload []byte) ([]byte, error) {
	if len(payload) > 0 {
		log.Printf("[auth] %s: unexpected CONNECT payload %x", c.Addr, payload)
	}
	return nil, nil
}

func (h *authHandler) OnMessage(c *prudp.Conn, msg []byte) {
	h.b.dispatch("auth", c, msg, func(p uint16) bool { return p == ProtoTicketGranting })
}

func (h *authHandler) OnDisconnect(c *prudp.Conn) {}

// ---- secure server ----

type secureHandler struct{ b *Backend }

func (h *secureHandler) OnConnect(c *prudp.Conn, payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("secure CONNECT without ticket")
	}
	r := rmc.NewReader(payload)
	ticket := r.Buffer()
	reqData := r.Buffer()
	if r.Err() != nil {
		return nil, fmt.Errorf("parse CONNECT payload: %v (payload %x)", r.Err(), payload)
	}
	sessionKey, pid, err := h.b.readServerTicket(ticket)
	if err != nil {
		return nil, fmt.Errorf("ticket: %v", err)
	}
	var plain []byte
	if p, err := kerberos.Decrypt(sessionKey, reqData); err == nil {
		plain = p
	} else {
		plain = kerberos.DecryptNoMAC(sessionKey, reqData)
		log.Printf("[secure] %s: request data has no valid HMAC (%v), using plain RC4", c.Addr, err)
	}
	if len(plain) < 12 {
		return nil, fmt.Errorf("request data too short: %x", plain)
	}
	reqPID := binary.LittleEndian.Uint32(plain[0:])
	cid := binary.LittleEndian.Uint32(plain[4:])
	check := binary.LittleEndian.Uint32(plain[8:])
	if reqPID != pid {
		return nil, fmt.Errorf("PID mismatch: ticket %d, request %d", pid, reqPID)
	}
	c.PID, c.SessionKey, c.CID = pid, sessionKey, cid
	if pid == PIDGuest {
		c.User = "guest"
	} else if a := h.b.Store.ByPID(pid); a != nil {
		c.User = a.Name
	}
	log.Printf("[secure] %s: authenticated as %q (pid %d, cid %d)", c.Addr, c.User, pid, cid)

	resp := make([]byte, 4)
	binary.LittleEndian.PutUint32(resp, check+1)
	if h.b.Cfg.EncryptCheck {
		resp = kerberos.Encrypt(sessionKey, resp)
	}
	w := &rmc.Writer{}
	w.Buffer(resp)
	return w.Bytes(), nil
}

func (h *secureHandler) OnMessage(c *prudp.Conn, msg []byte) {
	if c.PID == 0 {
		log.Printf("[secure] %s: message before authentication: %x", c.Addr, msg)
		return
	}
	h.b.dispatch("secure", c, msg, func(p uint16) bool { return p != ProtoTicketGranting })
}

func (h *secureHandler) OnDisconnect(c *prudp.Conn) {
	h.b.mu.Lock()
	current := h.b.sessions[c.PID] == c
	if current {
		delete(h.b.sessions, c.PID)
	}
	h.b.mu.Unlock()
	if current {
		h.b.dropPlayer(c)
	}
	if c.User != "" {
		log.Printf("[secure] %s (%s) logged out", c.User, c.Addr)
	}
}

func hexs(b []byte) string { return hex.EncodeToString(b) }
