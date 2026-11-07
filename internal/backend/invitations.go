package backend

import (
	"log"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// Invitations to a gathering (the lobby's INVITE slot). The game looks the
// player up with GetPID, checks GetStatus contains "Online", then calls
// Invite; the invited game polls GetInvitationsReceived.
//
// Invitation DDL: u32 idGathering, u32 idGuest, String strMessage.

type invitation struct {
	gid, host, guest uint32
	msg              string
}

func (inv *invitation) write(w *rmc.Writer) {
	w.U32(inv.gid)
	w.U32(inv.guest)
	w.String(inv.msg)
}

func writeInvitations(l []*invitation) *rmc.Writer {
	w := &rmc.Writer{}
	w.U32(uint32(len(l)))
	for _, inv := range l {
		inv.write(w)
	}
	return w
}

func containsPID(l []uint32, pid uint32) bool {
	for _, p := range l {
		if p == pid {
			return true
		}
	}
	return false
}

// removeInvitations drops invitations matching pred. Call with b.mu held.
func (b *Backend) removeInvitations(pred func(*invitation) bool) int {
	kept := b.invitations[:0]
	n := 0
	for _, inv := range b.invitations {
		if pred(inv) {
			n++
			continue
		}
		kept = append(kept, inv)
	}
	b.invitations = kept
	return n
}

// dropInvitations removes everything sent to or from a player who left.
func (b *Backend) dropInvitations(pid uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeInvitations(func(inv *invitation) bool { return inv.guest == pid || inv.host == pid })
}

func (b *Backend) registerInvitations() {
	reg := func(id uint32, name string, f Method) { b.register(ProtoMatchMaking, id, name, f) }

	reg(5, "Invite", func(c *Ctx) (*rmc.Writer, uint32) {
		gid, guests, msg := c.R.U32(), c.R.U32List(), c.R.String()
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.gatherings[gid] == nil {
			log.Printf("[secure]   %s invited %v to unknown gathering %d", c.who(), guests, gid)
			return boolResp(false), 0
		}
		for _, guest := range guests {
			if guest == 0 || guest == c.Conn.PID {
				continue
			}
			b.removeInvitations(func(inv *invitation) bool { return inv.gid == gid && inv.guest == guest })
			b.invitations = append(b.invitations, &invitation{gid: gid, host: c.Conn.PID, guest: guest, msg: msg})
			log.Printf("[secure]   %s invited %q (pid %d) to gathering %d", c.who(), b.nameOf(guest), guest, gid)
		}
		return boolResp(true), 0
	})
	b.registerQuiet(ProtoMatchMaking, 10, "GetInvitationsReceived", func(c *Ctx) (*rmc.Writer, uint32) {
		b.mu.Lock()
		defer b.mu.Unlock()
		var out []*invitation
		for _, inv := range b.invitations {
			if inv.guest == c.Conn.PID && b.gatherings[inv.gid] != nil {
				out = append(out, inv)
			}
		}
		return writeInvitations(out), 0
	})
	reg(9, "GetInvitationsSent", func(c *Ctx) (*rmc.Writer, uint32) {
		gid := c.R.U32()
		b.mu.Lock()
		defer b.mu.Unlock()
		var out []*invitation
		for _, inv := range b.invitations {
			if inv.gid == gid && inv.host == c.Conn.PID {
				out = append(out, inv)
			}
		}
		return writeInvitations(out), 0
	})
	answer := func(accept bool) Method {
		return func(c *Ctx) (*rmc.Writer, uint32) {
			gid, _ := c.R.U32(), c.R.String()
			b.mu.Lock()
			defer b.mu.Unlock()
			n := b.removeInvitations(func(inv *invitation) bool { return inv.gid == gid && inv.guest == c.Conn.PID })
			g := b.gatherings[gid]
			if !accept {
				log.Printf("[secure]   %s declined the invitation to gathering %d", c.who(), gid)
				return boolResp(n > 0), 0
			}
			if n == 0 || g == nil {
				log.Printf("[secure]   %s accepted a missing/expired invitation to gathering %d", c.who(), gid)
				return boolResp(false), 0
			}
			// The game does not call Participate after accepting: accepting
			// makes the player a participant (as in Quazal's own server).
			if !containsPID(g.Participants, c.Conn.PID) {
				if max := g.maxParticipants(); max > 0 && len(g.Participants) >= max {
					log.Printf("[secure]   %s accepted the invitation but gathering %d is full", c.who(), gid)
					return boolResp(false), 0
				}
				g.Participants = append(g.Participants, c.Conn.PID)
			}
			log.Printf("[secure]   %s accepted the invitation and joined gathering %d (%d players)", c.who(), gid, len(g.Participants))
			return boolResp(true), 0
		}
	}
	reg(6, "AcceptInvitation", answer(true))
	reg(7, "DeclineInvitation", answer(false))
	reg(8, "CancelInvitation", func(c *Ctx) (*rmc.Writer, uint32) {
		gid, guests, _ := c.R.U32(), c.R.U32List(), c.R.String()
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, guest := range guests {
			b.removeInvitations(func(inv *invitation) bool { return inv.gid == gid && inv.guest == guest })
		}
		return boolResp(true), 0
	})
}
