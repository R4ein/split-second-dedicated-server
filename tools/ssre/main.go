// ssre is a small static-analysis helper for SplitSecond.exe (32-bit PE).
// It finds strings, cross-references and callers, and disassembles code
// with annotations for strings, imports and MSVC RTTI vtables.
//
//	ssre <exe> str <substring>       find ASCII strings
//	ssre <exe> xref <hexVA>          find code that embeds the address
//	ssre <exe> callers <hexVA>       find direct E8 calls to a function
//	ssre <exe> dis <hexVA> [n]       disassemble n instructions
//	ssre <exe> fn <hexVA> [max]      disassemble the function containing VA
//	ssre <exe> rtti <substring>      list vtables whose class name matches
//	ssre <exe> vt <hexVA> [n]        dump n vtable slots
package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

type section struct {
	name     string
	va, size uint32
	data     []byte
	exec     bool
}

type image struct {
	base    uint32
	secs    []section
	imports map[uint32]string
	vtcache map[uint32]string
}

func load(path string) *image {
	f, err := pe.Open(path)
	must(err)
	oh := f.OptionalHeader.(*pe.OptionalHeader32)
	im := &image{base: oh.ImageBase, imports: map[uint32]string{}, vtcache: map[uint32]string{}}
	// SSRE_MEM points at a memdump of the running image (offset 0 = image
	// base); its contents replace the on-disk section data.
	var mem []byte
	if p := os.Getenv("SSRE_MEM"); p != "" {
		mem, err = os.ReadFile(p)
		must(err)
	}
	for _, s := range f.Sections {
		d, _ := s.Data()
		if uint32(len(d)) < s.VirtualSize {
			d = append(d, make([]byte, s.VirtualSize-uint32(len(d)))...)
		}
		if mem != nil && int(s.VirtualAddress+s.VirtualSize) <= len(mem) {
			d = mem[s.VirtualAddress : s.VirtualAddress+s.VirtualSize]
		}
		im.secs = append(im.secs, section{s.Name, oh.ImageBase + s.VirtualAddress, s.VirtualSize, d, s.Characteristics&0x20000000 != 0})
	}
	// import directory
	idir := oh.DataDirectory[1]
	for off := uint32(0); ; off += 20 {
		d := im.read(im.base+idir.VirtualAddress+off, 20)
		if d == nil || bytes.Equal(d, make([]byte, 20)) {
			break
		}
		oft := binary.LittleEndian.Uint32(d[0:])
		nameRVA := binary.LittleEndian.Uint32(d[12:])
		ft := binary.LittleEndian.Uint32(d[16:])
		dll := im.cstr(im.base + nameRVA)
		if oft == 0 {
			oft = ft
		}
		for i := uint32(0); ; i++ {
			e := im.u32(im.base + oft + 4*i)
			if e == 0 {
				break
			}
			var fn string
			if e&0x80000000 != 0 {
				fn = fmt.Sprintf("#%d", e&0xffff)
			} else {
				fn = im.cstr(im.base + e + 2)
			}
			im.imports[im.base+ft+4*i] = dll + "!" + fn
		}
	}
	return im
}

func (im *image) sec(va uint32) *section {
	for i := range im.secs {
		s := &im.secs[i]
		if va >= s.va && va < s.va+uint32(len(s.data)) {
			return s
		}
	}
	return nil
}

func (im *image) read(va, n uint32) []byte {
	s := im.sec(va)
	if s == nil || va+n > s.va+uint32(len(s.data)) {
		return nil
	}
	return s.data[va-s.va : va-s.va+n]
}

func (im *image) u32(va uint32) uint32 {
	d := im.read(va, 4)
	if d == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(d)
}

func (im *image) cstr(va uint32) string {
	s := im.sec(va)
	if s == nil {
		return ""
	}
	d := s.data[va-s.va:]
	if i := bytes.IndexByte(d, 0); i >= 0 {
		d = d[:i]
	}
	if len(d) > 200 {
		d = d[:200]
	}
	return string(d)
}

// printable returns the string at va if it looks like a real C string.
func (im *image) printable(va uint32) (string, bool) {
	s := im.sec(va)
	if s == nil || s.exec {
		return "", false
	}
	str := im.cstr(va)
	if len(str) < 3 {
		return "", false
	}
	for _, c := range []byte(str) {
		if (c < 0x20 || c > 0x7e) && c != '\n' && c != '\r' && c != '\t' {
			return "", false
		}
	}
	return str, true
}

// vtname resolves an MSVC vtable address to its class name via RTTI.
func (im *image) vtname(va uint32) string {
	if n, ok := im.vtcache[va]; ok {
		return n
	}
	name := ""
	col := im.u32(va - 4)
	if s := im.sec(col); s != nil && !s.exec && im.u32(col) == 0 {
		td := im.u32(col + 12)
		if n := im.cstr(td + 8); strings.HasPrefix(n, ".?A") {
			name = n
		}
	}
	im.vtcache[va] = name
	return name
}

func (im *image) annotate(v uint32) string {
	if n, ok := im.imports[v]; ok {
		return "IAT " + n
	}
	if n := im.vtname(v); n != "" {
		return "vtable " + n
	}
	if s, ok := im.printable(v); ok {
		return strconv.Quote(s)
	}
	return ""
}

func (im *image) decode(va uint32) (x86asm.Inst, error) {
	d := im.read(va, 16)
	if d == nil {
		s := im.sec(va)
		if s == nil {
			return x86asm.Inst{}, fmt.Errorf("unmapped")
		}
		d = s.data[va-s.va:]
	}
	return x86asm.Decode(d, 32)
}

func (im *image) line(va uint32, in x86asm.Inst) string {
	txt := x86asm.IntelSyntax(in, uint64(va), nil)
	var notes []string
	for _, a := range in.Args {
		switch a := a.(type) {
		case x86asm.Imm:
			if n := im.annotate(uint32(a)); n != "" {
				notes = append(notes, n)
			}
		case x86asm.Mem:
			if a.Base == 0 && a.Index == 0 {
				if n := im.annotate(uint32(a.Disp)); n != "" {
					notes = append(notes, n)
				}
			}
		case x86asm.Rel:
			t := va + uint32(in.Len) + uint32(int32(a))
			if j, err := im.decode(t); err == nil && j.Op == x86asm.JMP {
				if m, ok := j.Args[0].(x86asm.Mem); ok {
					if n, ok := im.imports[uint32(m.Disp)]; ok {
						notes = append(notes, "-> "+n)
					}
				}
			}
		}
	}
	raw := im.read(va, uint32(in.Len))
	out := fmt.Sprintf("%08X  %-20x %s", va, raw, txt)
	if len(notes) > 0 {
		out += "    ; " + strings.Join(notes, " | ")
	}
	return out
}

func (im *image) dis(va uint32, n int, stopAtRet bool) {
	for i := 0; i < n; i++ {
		in, err := im.decode(va)
		if err != nil {
			fmt.Printf("%08X  (bad: %v)\n", va, err)
			va++
			continue
		}
		fmt.Println(im.line(va, in))
		va += uint32(in.Len)
		if stopAtRet && in.Op == x86asm.RET {
			if b := im.read(va, 1); b != nil && (b[0] == 0xCC || b[0] == 0x90) {
				return
			}
		}
	}
}

// fnStart walks backwards to the start of the function containing va,
// using MSVC's int3 padding between functions as the boundary.
func (im *image) fnStart(va uint32) uint32 {
	s := im.sec(va)
	for p := va; p > s.va+2; p-- {
		d := s.data[p-s.va-1 : p-s.va+1]
		if d[0] == 0xCC && d[1] != 0xCC {
			return p
		}
		if va-p > 0x4000 {
			break
		}
	}
	return va
}

func (im *image) scan(pred func(sec *section, off int) bool) []uint32 {
	return im.scanSecs(true, pred)
}

func (im *image) scanSecs(execOnly bool, pred func(sec *section, off int) bool) []uint32 {
	var hits []uint32
	for i := range im.secs {
		s := &im.secs[i]
		if execOnly && !s.exec {
			continue
		}
		for off := 0; off+4 <= len(s.data); off++ {
			if pred(s, off) {
				hits = append(hits, s.va+uint32(off))
			}
		}
	}
	return hits
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: ssre <exe> <cmd> <arg> [n]")
		os.Exit(2)
	}
	im := load(os.Args[1])
	cmd, arg := os.Args[2], os.Args[3]
	num := func(def int) int {
		if len(os.Args) > 4 {
			n, err := strconv.Atoi(os.Args[4])
			must(err)
			return n
		}
		return def
	}
	hex := func(s string) uint32 {
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
		must(err)
		return uint32(v)
	}
	switch cmd {
	case "str":
		for _, s := range im.secs {
			if s.exec {
				continue
			}
			d := s.data
			for i := 0; i < len(d); {
				j := bytes.Index(d[i:], []byte(arg))
				if j < 0 {
					break
				}
				p := i + j
				st := p
				for st > 0 && d[st-1] >= 0x20 && d[st-1] <= 0x7e {
					st--
				}
				fmt.Printf("%08X  %q\n", s.va+uint32(st), im.cstr(s.va+uint32(st)))
				i = p + 1
			}
		}
	case "xref":
		t := hex(arg)
		for _, h := range im.scan(func(s *section, off int) bool { return binary.LittleEndian.Uint32(s.data[off:]) == t }) {
			fn := im.fnStart(h)
			fmt.Printf("ref @ %08X (fn ~%08X)\n", h, fn)
		}
	case "dref":
		// references from data (vtables, jump tables, function pointer tables)
		t := hex(arg)
		for _, h := range im.scanSecs(false, func(s *section, off int) bool {
			return !s.exec && off%4 == 0 && binary.LittleEndian.Uint32(s.data[off:]) == t
		}) {
			// walk back to the start of a vtable: the slot after an RTTI COL pointer
			vt := h
			for i := 0; i < 400; i++ {
				if im.vtname(vt) != "" {
					break
				}
				vt -= 4
			}
			if n := im.vtname(vt); n != "" {
				fmt.Printf("data ref @ %08X = %s slot %d (vtable %08X)\n", h, n, (h-vt)/4, vt)
			} else {
				fmt.Printf("data ref @ %08X\n", h)
			}
		}
	case "callers":
		t := hex(arg)
		for _, h := range im.scan(func(s *section, off int) bool {
			return off > 0 && s.data[off-1] == 0xE8 && s.va+uint32(off)+4+binary.LittleEndian.Uint32(s.data[off:]) == t
		}) {
			fmt.Printf("call @ %08X (fn ~%08X)\n", h-1, im.fnStart(h-1))
		}
	case "dis":
		im.dis(hex(arg), num(40), false)
	case "fn":
		st := im.fnStart(hex(arg))
		fmt.Printf("; function ~%08X\n", st)
		im.dis(st, num(400), true)
	case "rtti":
		var out []string
		for i := range im.secs {
			s := &im.secs[i]
			if s.exec {
				continue
			}
			for off := 4; off+4 <= len(s.data); off += 4 {
				va := s.va + uint32(off)
				col := binary.LittleEndian.Uint32(s.data[off-4:])
				if cs := im.sec(col); cs == nil || cs.exec {
					continue
				}
				if n := im.vtname(va); n != "" && strings.Contains(n, arg) {
					out = append(out, fmt.Sprintf("%08X  %s", va, n))
				}
			}
		}
		sort.Strings(out)
		fmt.Println(strings.Join(out, "\n"))
	case "vt":
		va := hex(arg)
		fmt.Printf("; %s\n", im.vtname(va))
		for i := 0; i < num(20); i++ {
			f := im.u32(va + uint32(4*i))
			fmt.Printf("[%2d] %08X\n", i, f)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
