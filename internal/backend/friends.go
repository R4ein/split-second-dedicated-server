package backend

import (
	"log"
	"path/filepath"
	"sort"
	"sync"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- Friends (20) ----
//
// Split/Second's Quazal build numbers the Friends methods differently from
// later NEX versions: 1 AddFriend(pid, details, message), 3
// AcceptFriendship(pid), 5 BlackList(pid, details), 7 ClearRelationship(pid)
// and 10 GetDetailedList(relationship, reversed) -> List<FriendData>.
//
// FriendData wire layout (client-side reader at 0xB042D0):
//
//	u32 pid, String name, u8 relationship, u32 details, String status
//
// The game polls method 10 with (1, false) for the friends list and
// (2, true) for incoming friend requests, about twice a second each.

// Relationship codes, as stored and as sent in FriendData.
const (
	relFriend  = 1 // mutual
	relPending = 2 // From asked To; To accepts or clears
	relBlocked = 3
)

type relation struct {
	From    uint32 `json:"from"`
	To      uint32 `json:"to"`
	Status  uint8  `json:"status"`
	Details uint32 `json:"details,omitempty"`
}

// social holds the friend graph, persisted to friends.json.
type social struct {
	mu        sync.Mutex
	path      string
	Relations []*relation `json:"relations"`
}

func (s *social) open(dir string) {
	s.path = filepath.Join(dir, "friends.json")
	loadJSON(s.path, s)
}

// save marshals under the lock; call without s.mu held.
func (s *social) save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	saveJSON(s.path, s)
}

// find returns the relation from a to b, in that direction.
func (s *social) find(a, b uint32) *relation {
	for _, r := range s.Relations {
		if r.From == a && r.To == b {
			return r
		}
	}
	return nil
}

// row is one FriendData entry before names and status are filled in.
type row struct {
	pid     uint32
	status  uint8
	details uint32
}

// rows lists the caller's relations of one kind. reversed selects
// relations that point at the caller instead of away from them;
// friendships are mutual, so both directions count.
func (s *social) rows(me uint32, status uint8, reversed bool) []row {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []row
	for _, r := range s.Relations {
		if r.Status != status {
			continue
		}
		switch {
		case r.Status == relFriend && r.From == me:
			out = append(out, row{r.To, r.Status, r.Details})
		case r.Status == relFriend && r.To == me:
			out = append(out, row{r.From, r.Status, r.Details})
		case !reversed && r.From == me:
			out = append(out, row{r.To, r.Status, r.Details})
		case reversed && r.To == me:
			out = append(out, row{r.From, r.Status, r.Details})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out
}

func (b *Backend) registerFriends() {
	b.registerQuiet(ProtoFriends, 10, "GetDetailedList", func(c *Ctx) (*rmc.Writer, uint32) {
		relationship, reversed := c.R.U8(), c.R.Bool()
		rows := b.social.rows(c.Conn.PID, relationship, reversed)
		w := &rmc.Writer{}
		w.U32(uint32(len(rows)))
		for _, r := range rows {
			w.U32(r.pid)
			w.String(b.nameOf(r.pid))
			w.U8(r.status)
			w.U32(r.details)
			w.String(b.statusOf(r.pid))
		}
		return w, 0
	})
	b.register(ProtoFriends, 1, "AddFriend", func(c *Ctx) (*rmc.Writer, uint32) {
		pid, details, msg := c.R.U32(), c.R.U32(), c.R.String()
		return boolResp(b.addFriend(c, pid, details, msg)), 0
	})
	b.register(ProtoFriends, 3, "AcceptFriendship", func(c *Ctx) (*rmc.Writer, uint32) {
		pid := c.R.U32()
		s := &b.social
		s.mu.Lock()
		r := s.find(pid, c.Conn.PID)
		ok := r != nil && r.Status == relPending
		if ok {
			r.Status = relFriend
		}
		s.mu.Unlock()
		if ok {
			s.save()
			log.Printf("[secure]   %s accepted friendship with %q (pid %d)", c.who(), b.nameOf(pid), pid)
		} else {
			log.Printf("[secure]   %s: no pending friend request from pid %d", c.who(), pid)
		}
		return boolResp(ok), 0
	})
	b.register(ProtoFriends, 5, "BlackList", func(c *Ctx) (*rmc.Writer, uint32) {
		pid, details := c.R.U32(), c.R.U32()
		s := &b.social
		s.mu.Lock()
		s.clearPair(c.Conn.PID, pid)
		s.Relations = append(s.Relations, &relation{From: c.Conn.PID, To: pid, Status: relBlocked, Details: details})
		s.mu.Unlock()
		s.save()
		log.Printf("[secure]   %s blacklisted %q (pid %d)", c.who(), b.nameOf(pid), pid)
		return boolResp(true), 0
	})
	b.register(ProtoFriends, 7, "ClearRelationship", func(c *Ctx) (*rmc.Writer, uint32) {
		pid := c.R.U32()
		s := &b.social
		s.mu.Lock()
		ok := s.clearPair(c.Conn.PID, pid)
		s.mu.Unlock()
		if ok {
			s.save()
		}
		log.Printf("[secure]   %s cleared relationship with %q (pid %d)", c.who(), b.nameOf(pid), pid)
		return boolResp(true), 0
	})
}

// addFriend sends a friend request; if the other player already asked,
// both become friends, like on the original servers. The game also calls
// this when inviting someone to a lobby.
func (b *Backend) addFriend(c *Ctx, pid, details uint32, msg string) bool {
	if pid == c.Conn.PID || b.nameOf(pid) == "" {
		return false
	}
	s := &b.social
	s.mu.Lock()
	defer func() { s.mu.Unlock(); s.save() }()
	if r := s.find(c.Conn.PID, pid); r != nil {
		return r.Status != relBlocked // request already recorded
	}
	if r := s.find(pid, c.Conn.PID); r != nil {
		switch r.Status {
		case relBlocked:
			return false
		case relPending:
			r.Status = relFriend
			log.Printf("[secure]   %s and %q are now friends", c.who(), b.nameOf(pid))
			return true
		case relFriend:
			return true
		}
	}
	s.Relations = append(s.Relations, &relation{From: c.Conn.PID, To: pid, Status: relPending, Details: details})
	log.Printf("[secure]   %s sent a friend request to %q (pid %d, msg %q)", c.who(), b.nameOf(pid), pid, msg)
	return true
}

// clearPair removes every relation between a and b. Call with s.mu held.
func (s *social) clearPair(a, b uint32) bool {
	kept := s.Relations[:0]
	removed := false
	for _, r := range s.Relations {
		if (r.From == a && r.To == b) || (r.From == b && r.To == a) {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	s.Relations = kept
	return removed
}

// statusOf is the status string shown in the friends list. The invite UI
// checks the same wording via AccountManagement.GetStatus.
func (b *Backend) statusOf(pid uint32) string {
	b.mu.Lock()
	_, online := b.sessions[pid]
	b.mu.Unlock()
	if online {
		return "Online"
	}
	return "Offline"
}
