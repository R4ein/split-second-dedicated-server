package backend

import (
	"log"

	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- NATTraversal (3) ----
//
// Hole punching between players. A player who wants to reach other
// stations asks the server to have them send probes back at the same time,
// which opens both routers' NAT mappings:
//
//	1 RequestProbeInitiation(List<StationURL> targets)
//	2 InitiateProbe(StationURL toProbe)          server -> client
//	3 RequestProbeInitiationExt(List<StationURL> targets, StationURL toProbe)
//
// The game implements method 2 itself (client-side handler at 0xB09E80).

const natInitiateProbe = 2

func (b *Backend) registerNATTraversal() {
	reg := func(id uint32, name string, f Method) { b.register(ProtoNATTraversal, id, name, f) }

	reg(1, "RequestProbeInitiation", func(c *Ctx) (*rmc.Writer, uint32) {
		targets := c.R.StringList()
		b.relayProbes(c, targets, tagURL(publicURL(c.Conn), c.Conn.PID, c.Conn.CID))
		return nil, 0
	})
	reg(3, "RequestProbeInitiationExt", func(c *Ctx) (*rmc.Writer, uint32) {
		targets, toProbe := c.R.StringList(), c.R.String()
		b.relayProbes(c, targets, toProbe)
		return nil, 0
	})
	reg(4, "ReportNATTraversalResult", func(c *Ctx) (*rmc.Writer, uint32) {
		log.Printf("[secure]   %s NAT traversal result: %x", c.who(), c.Msg.Body)
		c.R.Rest()
		return nil, 0
	})
	reg(5, "ReportNATProperties", func(c *Ctx) (*rmc.Writer, uint32) {
		log.Printf("[secure]   %s NAT properties: %x", c.who(), c.Msg.Body)
		c.R.Rest()
		return nil, 0
	})
}

// relayProbes asks every target station to probe toProbe. Runs inside a
// secure-server handler, so the server lock is already held for Send.
func (b *Backend) relayProbes(c *Ctx, targets []string, toProbe string) {
	seen := map[*prudp.Conn]bool{}
	for _, t := range targets {
		s := b.sessionForURL(t, c.Conn)
		if s == nil || s == c.Conn || seen[s] {
			if s == nil {
				log.Printf("[secure]   %s probe target %s: no player at that address", c.who(), t)
			}
			continue
		}
		seen[s] = true
		w := &rmc.Writer{}
		w.String(toProbe)
		b.request(s, ProtoNATTraversal, natInitiateProbe, w.Bytes())
		log.Printf("[secure]   NAT: asked %s to probe %s for %s", s.User, toProbe, c.who())
	}
}
