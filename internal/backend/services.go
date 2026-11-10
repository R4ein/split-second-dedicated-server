package backend

import (
	"log"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- TicketGranting (10) ----

func (b *Backend) registerTicketGranting() {
	b.register(ProtoTicketGranting, 1, "Login", func(c *Ctx) (*rmc.Writer, uint32) {
		return b.login(c, c.R.String())
	})
	b.register(ProtoTicketGranting, 2, "LoginEx", func(c *Ctx) (*rmc.Writer, uint32) {
		name := c.R.String()
		extra := c.R.Rest()
		log.Printf("[auth]   LoginEx extra data: %x", extra)
		return b.login(c, name)
	})
	b.register(ProtoTicketGranting, 3, "RequestTicket", func(c *Ctx) (*rmc.Writer, uint32) {
		src, dst := c.R.U32(), c.R.U32()
		if c.Conn.PID != 0 && src != c.Conn.PID {
			return nil, rmc.ErrRVInvalidPID
		}
		t, err := b.makeTicket(src, dst)
		if err != nil {
			log.Printf("[auth]   RequestTicket: %v", err)
			return nil, rmc.ErrRVInvalidPID
		}
		w := &rmc.Writer{}
		w.U32(rmc.ResultSuccess)
		w.Buffer(t)
		return w, 0
	})
	b.register(ProtoTicketGranting, 4, "GetPID", func(c *Ctx) (*rmc.Writer, uint32) {
		name := c.R.String()
		w := &rmc.Writer{}
		if name == "guest" {
			w.U32(PIDGuest)
		} else if a := b.Store.ByName(name); a != nil {
			w.U32(a.PID)
		} else {
			return nil, rmc.ErrRVInvalidUsername
		}
		return w, 0
	})
	b.register(ProtoTicketGranting, 5, "GetName", func(c *Ctx) (*rmc.Writer, uint32) {
		w := &rmc.Writer{}
		w.String(b.nameOf(c.R.U32()))
		return w, 0
	})
}

func (b *Backend) nameOf(pid uint32) string {
	switch pid {
	case PIDGuest:
		return "guest"
	case PIDAuthServer:
		return "Quazal Authentication"
	case PIDSecureServer:
		return "Quazal Rendez-Vous"
	}
	if a := b.Store.ByPID(pid); a != nil {
		return a.Name
	}
	return ""
}

// loginFailure reports a failed login. Split/Second's Quazal version reads
// the failure from the qResult return value of a successful RMC response.
func (b *Backend) loginFailure(code uint32) (*rmc.Writer, uint32) {
	if b.Cfg.LoginErrorsAsRMC {
		return nil, code
	}
	w := &rmc.Writer{}
	w.U32(code)
	w.U32(0)      // pidPrincipal
	w.Buffer(nil) // pbufResponse
	w.String("")  // RVConnectionData.m_urlRegularProtocols
	w.U32(0)      // RVConnectionData.m_lstSpecialProtocols
	w.String("")  // RVConnectionData.m_urlSpecialProtocols
	w.String("")  // strReturnMsg
	return w, 0
}

func (b *Backend) login(c *Ctx, name string) (*rmc.Writer, uint32) {
	var pid uint32
	if name == "guest" {
		pid = PIDGuest
	} else if a := b.Store.ByName(name); a != nil {
		pid = a.PID
	} else {
		log.Printf("[auth]   login for unknown account %q", name)
		return b.loginFailure(rmc.ErrRVInvalidUsername)
	}
	t, err := b.makeTicket(pid, PIDSecureServer)
	if err != nil {
		log.Printf("[auth]   ticket: %v", err)
		return nil, rmc.ErrCoreUnknown
	}
	c.Conn.PID, c.Conn.User = pid, name
	log.Printf("[auth]   %q -> pid %d, secure server %s", name, pid, b.SecureURL())
	w := &rmc.Writer{}
	w.U32(rmc.ResultSuccess)
	w.U32(pid)
	w.Buffer(t)
	// RVConnectionData
	w.String(b.SecureURL())
	w.U32(0) // special protocols: empty list
	// Special-protocols URL. Must be empty: the client tries to connect to
	// any non-empty value here before registering.
	w.String("")
	// strReturnMsg
	w.String("")
	return w, 0
}

// ---- SecureConnection (11) ----

func (b *Backend) registerSecureConnection() {
	b.register(ProtoSecureConnection, 1, "Register", func(c *Ctx) (*rmc.Writer, uint32) {
		urls := c.R.StringList()
		return b.registerURLs(c, urls)
	})
	b.register(ProtoSecureConnection, 4, "RegisterEx", func(c *Ctx) (*rmc.Writer, uint32) {
		urls := c.R.StringList()
		log.Printf("[secure]   RegisterEx extra data: %x", c.R.Rest())
		return b.registerURLs(c, urls)
	})
	// The game calls this with the lobby host's PID (the gathering's
	// pidHost) right after GetParticipantsURLs, and abandons the join if it
	// gets nothing back.
	b.register(ProtoSecureConnection, 3, "RequestURLs", func(c *Ctx) (*rmc.Writer, uint32) {
		cid, pid := c.R.U32(), c.R.U32()
		if pid == 0 && cid != 0 {
			pid = b.pidForCID(cid)
		}
		urls := b.urlsFor(pid, c.Conn)
		log.Printf("[secure]   %s RequestURLs cid=%d pid=%d (%q) -> %v", c.who(), cid, pid, b.nameOf(pid), urls)
		w := &rmc.Writer{}
		w.Bool(len(urls) > 0)
		w.StringList(urls)
		return w, 0
	})
	b.register(ProtoSecureConnection, 5, "TestConnectivity", func(c *Ctx) (*rmc.Writer, uint32) {
		w := &rmc.Writer{}
		w.Bool(true)
		return w, 0
	})
	b.register(ProtoSecureConnection, 6, "UpdateURLs", func(c *Ctx) (*rmc.Writer, uint32) {
		urls := c.R.StringList()
		log.Printf("[secure]   %s UpdateURLs %v", c.who(), urls)
		c.Conn.Data["urls"] = urls
		return nil, 0
	})
	b.register(ProtoSecureConnection, 8, "SendReport", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		data := c.R.QBuffer()
		log.Printf("[secure]   SendReport id=%d data=%x", id, data)
		return nil, 0
	})
}

// pidForCID finds the logged-in player with the given connection ID.
func (b *Backend) pidForCID(cid uint32) uint32 {
	b.mu.Lock()
	defer b.mu.Unlock()
	for pid, s := range b.sessions {
		if s.CID == cid {
			return pid
		}
	}
	return 0
}

func (b *Backend) registerURLs(c *Ctx, urls []string) (*rmc.Writer, uint32) {
	cid := b.newCID()
	c.Conn.CID = cid
	pub := tagURL(publicURL(c.Conn), c.Conn.PID, cid)
	log.Printf("[secure]   %s registered URLs %v; public %s", c.who(), urls, pub)
	c.Conn.Data["urls"] = urls
	b.mu.Lock()
	b.sessions[c.Conn.PID] = c.Conn
	b.mu.Unlock()
	w := &rmc.Writer{}
	w.U32(rmc.ResultSuccess)
	w.U32(cid)
	w.String(pub)
	return w, 0
}

// ---- AccountManagement (25) ----

func (b *Backend) registerAccountManagement() {
	// Results go in the qResult return value, as with Login.
	create := func(c *Ctx, name, key, email string, groups uint32) (*rmc.Writer, uint32) {
		if c.Conn.PID != PIDGuest {
			log.Printf("[secure]   CreateAccount from non-guest pid %d", c.Conn.PID)
		}
		w := &rmc.Writer{}
		a, err := b.Store.Create(name, ParseKey(key), email, groups)
		switch {
		case err == ErrExists:
			w.U32(rmc.ErrRVUsernameExists)
		case err != nil:
			log.Printf("[secure]   CreateAccount %q: %v", name, err)
			w.U32(rmc.ErrRVInvalidUsername)
		default:
			log.Printf("[secure]   created account %q (pid %d)", a.Name, a.PID)
			w.U32(rmc.ResultSuccess)
		}
		return w, 0
	}
	b.register(ProtoAccountManagement, 1, "CreateAccount", func(c *Ctx) (*rmc.Writer, uint32) {
		name, key, groups, email := c.R.String(), c.R.String(), c.R.U32(), c.R.String()
		log.Printf("[secure]   CreateAccount name=%q keylen=%d groups=%d email=%q", name, len(key), groups, email)
		return create(c, name, key, email, groups)
	})
	b.register(ProtoAccountManagement, 21, "CreateAccountWithCustomData", func(c *Ctx) (*rmc.Writer, uint32) {
		name, key, groups, email := c.R.String(), c.R.String(), c.R.U32(), c.R.String()
		log.Printf("[secure]   CreateAccountWithCustomData name=%q keylen=%d groups=%d email=%q custom=%x", name, len(key), groups, email, c.R.Rest())
		return create(c, name, key, email, groups)
	})
	b.register(ProtoAccountManagement, 26, "CustomCreateAccount", func(c *Ctx) (*rmc.Writer, uint32) {
		name, key, groups, email := c.R.String(), c.R.String(), c.R.U32(), c.R.String()
		log.Printf("[secure]   CustomCreateAccount name=%q keylen=%d groups=%d email=%q rest=%x", name, len(key), groups, email, c.R.Rest())
		w, code := create(c, name, key, email, groups)
		var pid uint32
		if a := b.Store.ByName(name); a != nil {
			pid = a.PID
		}
		w.U32(pid)
		return w, code
	})
	b.register(ProtoAccountManagement, 4, "ChangePassword", func(c *Ctx) (*rmc.Writer, uint32) {
		key := c.R.String()
		if err := b.Store.SetPassword(c.Conn.User, ParseKey(key)); err != nil {
			return nil, rmc.ErrRVInvalidUsername
		}
		w := &rmc.Writer{}
		w.Bool(true)
		return w, 0
	})
	b.register(ProtoAccountManagement, 24, "ChangePasswordByGuest", func(c *Ctx) (*rmc.Writer, uint32) {
		name, key, email := c.R.String(), c.R.String(), c.R.String()
		log.Printf("[secure]   ChangePasswordByGuest name=%q keylen=%d email=%q", name, len(key), email)
		return nil, rmc.ErrCoreAccessDenied
	})
	b.register(ProtoAccountManagement, 6, "GetName", func(c *Ctx) (*rmc.Writer, uint32) {
		w := &rmc.Writer{}
		w.String(b.nameOf(c.R.U32()))
		return w, 0
	})
	// The game treats a player as reachable when the status string contains
	// "Online" (checked before sending an invite).
	b.register(ProtoAccountManagement, 18, "GetStatus", func(c *Ctx) (*rmc.Writer, uint32) {
		pid := c.R.U32()
		status := b.statusOf(pid)
		log.Printf("[secure]   %s asked status of %q (pid %d): %s", c.who(), b.nameOf(pid), pid, status)
		w := &rmc.Writer{}
		w.String(status)
		return w, 0
	})
}
