package backend

import (
	"log"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- Friends (20) ----
//
// Split/Second's Quazal build numbers the Friends methods differently from
// later NEX versions. The client stubs are 1 (u32, u32, String), 3 (u32),
// 5 (u32, u32), 7 (u32) and 10 (u8 relationship, bool reversed) -> list.
// The game polls method 10 about twice a second for as long as it is
// online, and calls method 1 when inviting someone from a lobby.
//
// Friend lists are not stored yet (the FriendData layout is unverified), so
// the list stays empty and the relationship calls just succeed.

func (b *Backend) registerFriends() {
	b.registerQuiet(ProtoFriends, 10, "GetDetailedList", func(c *Ctx) (*rmc.Writer, uint32) {
		c.R.U8()   // relationship
		c.R.Bool() // reversed
		w := &rmc.Writer{}
		w.U32(0) // empty list
		return w, 0
	})
	b.register(ProtoFriends, 1, "AddFriend", func(c *Ctx) (*rmc.Writer, uint32) {
		pid, details, msg := c.R.U32(), c.R.U32(), c.R.String()
		log.Printf("[secure]   %s added %q (pid %d) as friend (details %d, msg %q)", c.who(), b.nameOf(pid), pid, details, msg)
		return boolResp(true), 0
	})
	for _, m := range []struct {
		id   uint32
		name string
		args int
	}{{3, "AcceptFriendship", 1}, {5, "BlackList", 2}, {7, "ClearRelationship", 1}} {
		m := m
		b.register(ProtoFriends, m.id, m.name, func(c *Ctx) (*rmc.Writer, uint32) {
			pid := c.R.U32()
			if m.args == 2 {
				c.R.U32()
			}
			log.Printf("[secure]   %s %s %q (pid %d)", c.who(), m.name, b.nameOf(pid), pid)
			return boolResp(true), 0
		})
	}
}
