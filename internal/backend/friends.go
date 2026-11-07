package backend

import (
	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- Friends (20) ----
//
// Split/Second's Quazal build numbers the Friends methods differently from
// later NEX versions. The client stubs are 1 (u32, u32, String), 3 (u32),
// 5 (u32, u32), 7 (u32) and 10 (u8 relationship, bool reversed) -> list.
// The game polls method 10 about twice a second for as long as it is
// online. Friends lists are not stored yet, so it always gets an empty list.

func (b *Backend) registerFriends() {
	b.registerQuiet(ProtoFriends, 10, "GetDetailedList", func(c *Ctx) (*rmc.Writer, uint32) {
		c.R.U8()   // relationship
		c.R.Bool() // reversed
		w := &rmc.Writer{}
		w.U32(0) // empty list
		return w, 0
	})
}
