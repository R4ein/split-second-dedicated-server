package backend

import (
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"sync"

	"github.com/R4ein/split-second-dedicated-server/internal/rmc"
)

// ---- RVLeaderboard (101) ----
//
// Split/Second's custom stats and leaderboard service. The client stubs
// live at 0x9FE060 (method 1), 0x9FE1E0 (2) and 0x9FE370 (3), all called
// on the client registered with protocol ID 0x65 (0x9FD911).
//
// Wire types (argument writers 0xA02BD0/0xA04D30/0xA04FC0, row reader
// 0xA04E70; every list is a u32 count followed by the elements):
//
//	Property   = u32 id, String name, u32 flags, 6 x f64
//	StatEntry  = u32 board, u32 aux, f64 c, f64 d, List<Property>
//	RangeQuery = u32 board, u32 offset, u32 count, bool order, u32 arg
//	PIDQuery   = u32 board, List<u32> pids
//
//	1 SubmitStats(bool final, List<StatEntry>)  -> (no return values)
//	2 QueryStatsByRange(List<RangeQuery>)       -> List<StatEntry>
//	3 QueryStatsByPIDs(List<PIDQuery>)          -> List<StatEntry>
//
// Rows reuse the StatEntry shape (class cRVLeaderboardStats). The first
// two fields are sent back as (pid, rank): not yet verified against the
// real game, so query handlers log what they return.

type statProp struct {
	ID    uint32     `json:"id"`
	Name  string     `json:"name,omitempty"`
	Flags uint32     `json:"flags,omitempty"`
	V     [6]float64 `json:"v"`
}

type statEntry struct {
	Aux   uint32     `json:"aux,omitempty"`
	C     float64    `json:"c"`
	D     float64    `json:"d"`
	Props []statProp `json:"props,omitempty"`
}

// statsStore holds every player's submitted stats per leaderboard,
// persisted to stats.json.
type statsStore struct {
	mu   sync.Mutex
	path string
	// Boards[board][pid] = that player's entry on the board.
	Boards map[uint32]map[uint32]*statEntry `json:"boards"`
}

func (s *statsStore) open(dir string) {
	s.path = filepath.Join(dir, "stats.json")
	loadJSON(s.path, s)
	if s.Boards == nil {
		s.Boards = map[uint32]map[uint32]*statEntry{}
	}
}

// save marshals under the lock; call without s.mu held.
func (s *statsStore) save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	saveJSON(s.path, s)
}

// rankedRow is one leaderboard row for a query response.
type rankedRow struct {
	pid, rank uint32
	e         statEntry
}

// board returns a board's entries ranked by C, descending when desc.
// Equal scores tie-break on D, then on pid for a stable order.
func (s *statsStore) board(id uint32, desc bool) []rankedRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []rankedRow
	for pid, e := range s.Boards[id] {
		rows = append(rows, rankedRow{pid: pid, e: *e})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.e.C != b.e.C {
			return (a.e.C > b.e.C) == desc
		}
		if a.e.D != b.e.D {
			return (a.e.D > b.e.D) == desc
		}
		return a.pid < b.pid
	})
	for i := range rows {
		rows[i].rank = uint32(i + 1)
	}
	return rows
}

func readProps(r *rmc.Reader) []statProp {
	n := int(r.U32())
	var props []statProp
	for i := 0; i < n && r.Err() == nil; i++ {
		p := statProp{ID: r.U32(), Name: r.String(), Flags: r.U32()}
		for j := range p.V {
			p.V[j] = r.F64()
		}
		props = append(props, p)
	}
	return props
}

func writeRow(w *rmc.Writer, row rankedRow) {
	w.U32(row.pid)
	w.U32(row.rank)
	w.F64(row.e.C)
	w.F64(row.e.D)
	w.U32(uint32(len(row.e.Props)))
	for _, p := range row.e.Props {
		w.U32(p.ID)
		w.String(p.Name)
		w.U32(p.Flags)
		for _, v := range p.V {
			w.F64(v)
		}
	}
}

func (b *Backend) registerRVLeaderboard() {
	reg := func(id uint32, name string, f Method) { b.register(ProtoRVLeaderboard, id, name, f) }

	reg(1, "SubmitStats", func(c *Ctx) (*rmc.Writer, uint32) {
		final := c.R.Bool()
		n := int(c.R.U32())
		s := &b.stats
		var boards []uint32
		s.mu.Lock()
		for i := 0; i < n && c.R.Err() == nil; i++ {
			board := c.R.U32()
			e := &statEntry{Aux: c.R.U32(), C: c.R.F64(), D: c.R.F64(), Props: readProps(c.R)}
			if c.R.Err() != nil {
				break
			}
			if s.Boards[board] == nil {
				s.Boards[board] = map[uint32]*statEntry{}
			}
			s.Boards[board][c.Conn.PID] = e
			boards = append(boards, board)
		}
		s.mu.Unlock()
		if c.R.Err() != nil {
			log.Printf("[secure]   %s SubmitStats: bad body: %x", c.who(), c.Msg.Body)
			return nil, rmc.ErrCoreInvalidArg
		}
		s.save()
		log.Printf("[secure]   %s submitted stats for boards %v (final=%v)", c.who(), boards, final)
		return &rmc.Writer{}, 0
	})

	reg(2, "QueryStatsByRange", func(c *Ctx) (*rmc.Writer, uint32) {
		n := int(c.R.U32())
		var out []rankedRow
		desc := ""
		for i := 0; i < n && c.R.Err() == nil; i++ {
			board, offset, count := c.R.U32(), c.R.U32(), c.R.U32()
			order, arg := c.R.Bool(), c.R.U32()
			rows := b.stats.board(board, !order)
			if int(offset) < len(rows) {
				rows = rows[offset:]
			} else {
				rows = nil
			}
			if count > 0 && int(count) < len(rows) {
				rows = rows[:count]
			}
			out = append(out, rows...)
			desc += fmt.Sprintf(" board %d (offset %d count %d order %v arg %d): %d rows;",
				board, offset, count, order, arg, len(rows))
		}
		if c.R.Err() != nil {
			return nil, rmc.ErrCoreInvalidArg
		}
		log.Printf("[secure]   %s QueryStatsByRange:%s", c.who(), desc)
		w := &rmc.Writer{}
		w.U32(uint32(len(out)))
		for _, row := range out {
			writeRow(w, row)
		}
		return w, 0
	})

	reg(3, "QueryStatsByPIDs", func(c *Ctx) (*rmc.Writer, uint32) {
		n := int(c.R.U32())
		var out []rankedRow
		desc := ""
		for i := 0; i < n && c.R.Err() == nil; i++ {
			board := c.R.U32()
			pids := c.R.U32List()
			found := 0
			for _, row := range b.stats.board(board, true) {
				if containsPID(pids, row.pid) {
					out = append(out, row)
					found++
				}
			}
			desc += fmt.Sprintf(" board %d pids %v: %d rows;", board, pids, found)
		}
		if c.R.Err() != nil {
			return nil, rmc.ErrCoreInvalidArg
		}
		log.Printf("[secure]   %s QueryStatsByPIDs:%s", c.who(), desc)
		w := &rmc.Writer{}
		w.U32(uint32(len(out)))
		for _, row := range out {
			writeRow(w, row)
		}
		return w, 0
	})
}
