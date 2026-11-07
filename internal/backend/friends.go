package backend

import (
	"log"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- Friends (20) ----
//
// Split/Second's Quazal build numbers the Friends methods differently from
// later NEX versions; method 10 takes (u8 relationship, bool reversed) and
// is polled right after login. Friends lists are not stored yet, so every
// list query returns an empty list.

func (b *Backend) registerFriends() {
	b.register(ProtoFriends, 10, "GetDetailedList", func(c *Ctx) (*rmc.Writer, uint32) {
		rel, rev := c.R.U8(), c.R.Bool()
		if c.Conn.Data["friends_logged"] == nil {
			log.Printf("[secure]   friends list query relationship=%d reversed=%v -> empty", rel, rev)
			c.Conn.Data["friends_logged"] = true
		}
		w := &rmc.Writer{}
		w.U32(0) // empty list
		return w, 0
	})
}
