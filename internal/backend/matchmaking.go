package backend

import (
	"encoding/binary"
	"log"
	"regexp"
	"sort"
	"strings"

	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- MatchMaking (21) ----
//
// Gatherings arrive as AnyDataHolder blobs. Split/Second uses the class
// "ATVGameSession": the standard Quazal Gathering header followed by
// game-specific fields, which are stored and returned untouched.
//
// Gathering header layout:
//
//	0  u32 idMyself   4  u32 pidOwner   8  u32 pidHost
//	12 u16 minParticipants   14 u16 maxParticipants
//	16 u32 participationPolicy   20 u32 policyArgument
//	24 u32 flags   28 u32 state   32 String description
//
// The server owns idMyself, pidOwner and pidHost: the game registers and
// updates gatherings with zeros there. Joiners read pidHost and ask
// SecureConnection.RequestURLs for that player's stations, so a zero host
// makes every join fail ("lobby no longer exists").
const gatheringHeaderLen = 32

type gathering struct {
	ID           uint32
	Type         string
	Data         []byte
	Owner        uint32
	Description  string
	Participants []uint32
	SessionURL   string
	LocalURLs    []string
}

func (g *gathering) setU32(off int, v uint32) {
	if len(g.Data) >= off+4 {
		binary.LittleEndian.PutUint32(g.Data[off:], v)
	}
}

// stamp writes the server-owned header fields into the stored data,
// overwriting whatever the client sent (the game sends zeros). The owner is
// always the host: joiners read pidHost and call RequestURLs with it.
func (g *gathering) stamp() {
	g.setU32(0, g.ID)
	g.setU32(4, g.Owner)
	g.setU32(8, g.Owner)
}

func (g *gathering) u32(off int) uint32 {
	if len(g.Data) >= off+4 {
		return binary.LittleEndian.Uint32(g.Data[off:])
	}
	return 0
}

func (g *gathering) maxParticipants() int {
	if len(g.Data) >= 16 {
		return int(binary.LittleEndian.Uint16(g.Data[14:]))
	}
	return 0
}

func (g *gathering) write(w *rmc.Writer) {
	w.String(g.Type)
	w.U32(uint32(len(g.Data) + 4))
	w.U32(uint32(len(g.Data)))
	w.Write(g.Data)
}

func readAnyData(r *rmc.Reader) (string, []byte) {
	typ := r.String()
	r.U32() // outer length (inner + 4)
	data := r.Buffer()
	return typ, data
}

func parseDescription(data []byte) string {
	if len(data) < gatheringHeaderLen+2 {
		return ""
	}
	return rmc.NewReader(data[gatheringHeaderLen:]).String()
}

type resultRange struct{ offset, size uint32 }

func readRange(r *rmc.Reader) resultRange { return resultRange{r.U32(), r.U32()} }

func (rr resultRange) apply(gs []*gathering) []*gathering {
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	if int(rr.offset) >= len(gs) {
		return nil
	}
	gs = gs[rr.offset:]
	if rr.size != 0 && rr.size != 0xffffffff && int(rr.size) < len(gs) {
		gs = gs[:rr.size]
	}
	return gs
}

// writeGatherings serializes gatherings under the backend lock: handlers on
// other goroutines (e.g. a timeout's dropPlayer) mutate gathering data, so
// unlocked reads of it would race.
func (b *Backend) writeGatherings(gs []*gathering) *rmc.Writer {
	b.mu.Lock()
	defer b.mu.Unlock()
	w := &rmc.Writer{}
	w.U32(uint32(len(gs)))
	for _, g := range gs {
		g.write(w)
	}
	return w
}

func boolResp(v bool) *rmc.Writer {
	w := &rmc.Writer{}
	w.Bool(v)
	return w
}

// find returns gatherings matching pred, skipping full or closed ones only
// when the caller asks for joinable results.
func (b *Backend) find(pred func(g *gathering) bool) []*gathering {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*gathering
	for _, g := range b.gatherings {
		if pred(g) {
			out = append(out, g)
		}
	}
	return out
}

func (b *Backend) gatheringByID(id uint32) *gathering {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gatherings[id]
}

// likeToRegexp converts an SQL LIKE pattern to an anchored regexp.
func likeToRegexp(p string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString("(?s)^")
	for _, c := range p {
		switch c {
		case '%':
			sb.WriteString(".*")
		case '_':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

func (b *Backend) registerMatchMaking() {
	reg := func(id uint32, name string, f Method) { b.register(ProtoMatchMaking, id, name, f) }
	logBody := func(c *Ctx) { log.Printf("[secure]   body=%x", c.Msg.Body) }
	b.registerInvitations()

	reg(1, "RegisterGathering", func(c *Ctx) (*rmc.Writer, uint32) {
		typ, data := readAnyData(c.R)
		if c.R.Err() != nil || len(data) < gatheringHeaderLen {
			logBody(c)
			return nil, rmc.ErrCoreInvalidArg
		}
		b.mu.Lock()
		b.nextGID++
		g := &gathering{ID: b.nextGID, Type: typ, Data: data, Owner: c.Conn.PID, Description: parseDescription(data)}
		g.stamp()
		b.gatherings[g.ID] = g
		b.mu.Unlock()
		log.Printf("[secure]   %s registered gathering %d (%s %q, max %d) data=%x", c.Conn.User, g.ID, typ, g.Description, g.maxParticipants(), data)
		w := &rmc.Writer{}
		w.U32(g.ID)
		return w, 0
	})
	reg(2, "UnregisterGathering", func(c *Ctx) (*rmc.Writer, uint32) {
		return boolResp(b.deleteGathering(c.Conn.PID, c.R.U32())), 0
	})
	reg(3, "UnregisterGatherings", func(c *Ctx) (*rmc.Writer, uint32) {
		ok := true
		for _, id := range c.R.U32List() {
			ok = b.deleteGathering(c.Conn.PID, id) && ok
		}
		return boolResp(ok), 0
	})
	reg(4, "UpdateGathering", func(c *Ctx) (*rmc.Writer, uint32) {
		typ, data := readAnyData(c.R)
		if c.R.Err() != nil || len(data) < gatheringHeaderLen {
			logBody(c)
			return nil, rmc.ErrCoreInvalidArg
		}
		id := binary.LittleEndian.Uint32(data)
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		if g == nil || g.Owner != c.Conn.PID {
			log.Printf("[secure]   update of unknown/foreign gathering %d", id)
			return boolResp(false), 0
		}
		g.Type, g.Data, g.Description = typ, data, parseDescription(data)
		g.stamp()
		log.Printf("[secure]   gathering %d updated (%q) data=%x", id, g.Description, g.Data)
		return boolResp(true), 0
	})
	reg(11, "Participate", func(c *Ctx) (*rmc.Writer, uint32) {
		id, msg := c.R.U32(), c.R.String()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		if g == nil {
			return boolResp(false), 0
		}
		for _, p := range g.Participants {
			if p == c.Conn.PID {
				return boolResp(true), 0
			}
		}
		if max := g.maxParticipants(); max > 0 && len(g.Participants) >= max {
			log.Printf("[secure]   %s cannot join full gathering %d", c.Conn.User, id)
			return boolResp(false), 0
		}
		g.Participants = append(g.Participants, c.Conn.PID)
		log.Printf("[secure]   %s joined gathering %d (%d players) msg=%q", c.Conn.User, id, len(g.Participants), msg)
		return boolResp(true), 0
	})
	reg(12, "CancelParticipation", func(c *Ctx) (*rmc.Writer, uint32) {
		id, _ := c.R.U32(), c.R.String()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		if g == nil {
			return boolResp(false), 0
		}
		g.Participants = removePID(g.Participants, c.Conn.PID)
		log.Printf("[secure]   %s left gathering %d", c.Conn.User, id)
		return boolResp(true), 0
	})
	reg(13, "GetParticipants", func(c *Ctx) (*rmc.Writer, uint32) {
		g := b.gatheringByID(c.R.U32())
		w := &rmc.Writer{}
		if g == nil {
			w.U32(0)
			return w, 0
		}
		b.mu.Lock()
		w.U32List(g.Participants)
		b.mu.Unlock()
		return w, 0
	})
	// URLs of all participants in join order (host first), each tagged with
	// PID, including the caller's own. The game (0xA29D90) walks the list
	// until it finds its own PID and probes every station before it; it
	// reads past the end and crashes if its own entry is missing.
	reg(16, "GetParticipantsURLs", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		g := b.gatheringByID(id)
		parts := []uint32{}
		if g != nil {
			b.mu.Lock()
			parts = append(parts, g.Owner)
			for _, p := range g.Participants {
				if p != g.Owner {
					parts = append(parts, p)
				}
			}
			b.mu.Unlock()
		}
		if !containsPID(parts, c.Conn.PID) {
			parts = append(parts, c.Conn.PID)
		}
		var urls []string
		for _, p := range parts {
			if p == c.Conn.PID {
				urls = append(urls, ownURLs(c.Conn)...)
				continue
			}
			urls = append(urls, b.urlsFor(p, c.Conn)...)
		}
		log.Printf("[secure]   %s asked URLs of gathering %d: %v", c.who(), id, urls)
		w := &rmc.Writer{}
		w.StringList(urls)
		return w, 0
	})
	reg(17, "FindByType", func(c *Ctx) (*rmc.Writer, uint32) {
		typ, rr := c.R.String(), readRange(c.R)
		return b.writeGatherings(rr.apply(b.find(func(g *gathering) bool { return g.Type == typ }))), 0
	})
	reg(18, "FindByDescription", func(c *Ctx) (*rmc.Writer, uint32) {
		d, rr := c.R.String(), readRange(c.R)
		log.Printf("[secure]   FindByDescription %q", d)
		return b.writeGatherings(rr.apply(b.find(func(g *gathering) bool { return g.Description == d }))), 0
	})
	reg(19, "FindByDescriptionRegex", func(c *Ctx) (*rmc.Writer, uint32) {
		d, rr := c.R.String(), readRange(c.R)
		re, err := regexp.Compile(d)
		log.Printf("[secure]   FindByDescriptionRegex %q", d)
		if err != nil {
			return b.writeGatherings(nil), 0
		}
		return b.writeGatherings(rr.apply(b.find(func(g *gathering) bool { return re.MatchString(g.Description) }))), 0
	})
	reg(37, "FindByDescriptionLike", func(c *Ctx) (*rmc.Writer, uint32) {
		d, rr := c.R.String(), readRange(c.R)
		re, err := likeToRegexp(d)
		log.Printf("[secure]   FindByDescriptionLike %q", d)
		if err != nil {
			return b.writeGatherings(nil), 0
		}
		return b.writeGatherings(rr.apply(b.find(func(g *gathering) bool { return re.MatchString(g.Description) }))), 0
	})
	reg(20, "FindByID", func(c *Ctx) (*rmc.Writer, uint32) {
		ids := c.R.U32List()
		want := map[uint32]bool{}
		for _, id := range ids {
			want[id] = true
		}
		return b.writeGatherings(b.find(func(g *gathering) bool { return want[g.ID] })), 0
	})
	reg(21, "FindBySingleID", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		w := &rmc.Writer{}
		w.Bool(g != nil)
		if g != nil {
			g.write(w)
		} else {
			w.String("")
			w.U32(4)
			w.U32(0)
		}
		return w, 0
	})
	reg(22, "FindByOwner", func(c *Ctx) (*rmc.Writer, uint32) {
		pid, rr := c.R.U32(), readRange(c.R)
		return b.writeGatherings(rr.apply(b.find(func(g *gathering) bool { return g.Owner == pid }))), 0
	})
	reg(23, "FindByParticipants", func(c *Ctx) (*rmc.Writer, uint32) {
		pids := c.R.U32List()
		return b.writeGatherings(b.find(func(g *gathering) bool {
			for _, p := range pids {
				for _, q := range g.Participants {
					if p == q {
						return true
					}
				}
			}
			return false
		})), 0
	})
	reg(26, "LaunchSession", func(c *Ctx) (*rmc.Writer, uint32) {
		id, url := c.R.U32(), c.R.String()
		return boolResp(b.setSessionURL(c, id, url)), 0
	})
	reg(27, "UpdateSessionURL", func(c *Ctx) (*rmc.Writer, uint32) {
		id, url := c.R.U32(), c.R.String()
		return boolResp(b.setSessionURL(c, id, url)), 0
	})
	reg(28, "GetSessionURL", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		w := &rmc.Writer{}
		if g == nil || g.SessionURL == "" {
			w.Bool(false)
			w.String("")
			return w, 0
		}
		w.Bool(true)
		w.String(g.SessionURL)
		return w, 0
	})
	reg(41, "GetSessionURLs", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		var urls []string
		if g != nil {
			if g.SessionURL != "" {
				urls = append(urls, g.SessionURL)
			}
			urls = append(urls, g.LocalURLs...)
		}
		w := &rmc.Writer{}
		w.StringList(urls)
		return w, 0
	})
	reg(29, "GetState", func(c *Ctx) (*rmc.Writer, uint32) {
		id := c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		w := &rmc.Writer{}
		w.Bool(g != nil)
		if g != nil {
			w.U32(g.u32(28))
		} else {
			w.U32(0)
		}
		return w, 0
	})
	reg(30, "SetState", func(c *Ctx) (*rmc.Writer, uint32) {
		id, st := c.R.U32(), c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.gatherings[id]
		if g == nil {
			return boolResp(false), 0
		}
		g.setU32(28, st)
		log.Printf("[secure]   gathering %d state -> %d", id, st)
		return boolResp(true), 0
	})
	reg(31, "ReportStats", func(c *Ctx) (*rmc.Writer, uint32) {
		logBody(c)
		return boolResp(true), 0
	})
	reg(33, "DeleteGathering", func(c *Ctx) (*rmc.Writer, uint32) {
		return boolResp(b.deleteGathering(c.Conn.PID, c.R.U32())), 0
	})
	reg(38, "RegisterLocalURL", func(c *Ctx) (*rmc.Writer, uint32) {
		id, url := c.R.U32(), c.R.String()
		b.addLocalURLs(id, c.Conn.PID, []string{url})
		return nil, 0
	})
	reg(39, "RegisterLocalURLs", func(c *Ctx) (*rmc.Writer, uint32) {
		id, urls := c.R.U32(), c.R.StringList()
		b.addLocalURLs(id, c.Conn.PID, urls)
		return nil, 0
	})
}

func (b *Backend) setSessionURL(c *Ctx, id uint32, url string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.gatherings[id]
	if g == nil {
		return false
	}
	g.SessionURL = url
	log.Printf("[secure]   %s set session URL of gathering %d: %s", c.Conn.User, id, url)
	return true
}

func (b *Backend) addLocalURLs(id, pid uint32, urls []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if g := b.gatherings[id]; g != nil && g.Owner == pid {
		g.LocalURLs = append(g.LocalURLs, urls...)
		log.Printf("[secure]   gathering %d local URLs %v", id, urls)
	}
}

func (b *Backend) deleteGathering(pid, id uint32) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.gatherings[id]
	if g == nil || g.Owner != pid {
		return false
	}
	delete(b.gatherings, id)
	b.removeInvitations(func(inv *invitation) bool { return inv.gid == id })
	log.Printf("[secure]   gathering %d removed", id)
	return true
}

// dropPlayer removes a disconnected player's gatherings and participation.
func (b *Backend) dropPlayer(c *prudp.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, g := range b.gatherings {
		if g.Owner == c.PID {
			delete(b.gatherings, id)
			b.removeInvitations(func(inv *invitation) bool { return inv.gid == id })
			log.Printf("[secure]   gathering %d removed (owner left)", id)
			continue
		}
		g.Participants = removePID(g.Participants, c.PID)
	}
}

func removePID(l []uint32, pid uint32) []uint32 {
	out := l[:0]
	for _, p := range l {
		if p != pid {
			out = append(out, p)
		}
	}
	return out
}
