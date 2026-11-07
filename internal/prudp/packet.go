// Package prudp implements the Quazal PRUDP v0 transport used by the PC
// version of Split/Second (Quazal Rendez-Vous / NetZ, circa 2010).
package prudp

import (
	"bytes"
	"compress/zlib"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

type PacketType uint8

const (
	TypeSyn        PacketType = 0
	TypeConnect    PacketType = 1
	TypeData       PacketType = 2
	TypeDisconnect PacketType = 3
	TypePing       PacketType = 4
)

func (t PacketType) String() string {
	switch t {
	case TypeSyn:
		return "SYN"
	case TypeConnect:
		return "CONNECT"
	case TypeData:
		return "DATA"
	case TypeDisconnect:
		return "DISCONNECT"
	case TypePing:
		return "PING"
	}
	return fmt.Sprintf("TYPE%d", uint8(t))
}

const (
	FlagAck      uint8 = 1
	FlagReliable uint8 = 2
	FlagNeedAck  uint8 = 4
	FlagHasSize  uint8 = 8
)

func FlagString(f uint8) string {
	var s []string
	for _, x := range []struct {
		f uint8
		n string
	}{{FlagAck, "ACK"}, {FlagReliable, "REL"}, {FlagNeedAck, "NEEDACK"}, {FlagHasSize, "SIZE"}} {
		if f&x.f != 0 {
			s = append(s, x.n)
			f &^= x.f
		}
	}
	if f != 0 {
		s = append(s, fmt.Sprintf("0x%x", f))
	}
	return strings.Join(s, "|")
}

// Layout describes how the type/flags byte is split. Quazal PC titles use
// 3 bits of type and 5 bits of flags; some NEX titles use 4/4.
type Layout int

const (
	LayoutUnknown Layout = iota
	Layout3x5            // type = b & 7,   flags = b >> 3
	Layout4x4            // type = b & 0xF, flags = b >> 4
)

func (l Layout) String() string {
	switch l {
	case Layout3x5:
		return "type3/flags5"
	case Layout4x4:
		return "type4/flags4"
	}
	return "unknown"
}

func (l Layout) split(b byte) (PacketType, uint8) {
	if l == Layout4x4 {
		return PacketType(b & 0xF), b >> 4
	}
	return PacketType(b & 7), b >> 3
}

func (l Layout) join(t PacketType, f uint8) byte {
	if l == Layout4x4 {
		return byte(t)&0xF | f<<4
	}
	return byte(t)&7 | f<<3
}

// Packet is one PRUDP v0 datagram. Payload is the on-wire (encoded) payload.
type Packet struct {
	Src, Dst  uint8 // virtual ports: stream type << 4 | port
	Type      PacketType
	Flags     uint8
	Session   uint8
	Signature uint32
	Seq       uint16
	ConnSig   uint32 // SYN / CONNECT only
	Fragment  uint8  // DATA only
	Payload   []byte
	Checksum  uint8
}

func (p *Packet) String() string {
	s := fmt.Sprintf("%s [%s] %02x->%02x sess=%02x sig=%08x seq=%d", p.Type, FlagString(p.Flags), p.Src, p.Dst, p.Session, p.Signature, p.Seq)
	if p.Type == TypeSyn || p.Type == TypeConnect {
		s += fmt.Sprintf(" csig=%08x", p.ConnSig)
	}
	if p.Type == TypeData {
		s += fmt.Sprintf(" frag=%d", p.Fragment)
	}
	return s + fmt.Sprintf(" len=%d", len(p.Payload))
}

func Decode(b []byte, l Layout) (*Packet, error) {
	if len(b) < 11 {
		return nil, errors.New("packet too short")
	}
	p := &Packet{Src: b[0], Dst: b[1], Session: b[3]}
	p.Type, p.Flags = l.split(b[2])
	p.Signature = binary.LittleEndian.Uint32(b[4:])
	p.Seq = binary.LittleEndian.Uint16(b[8:])
	off := 10
	body := b[:len(b)-1]
	p.Checksum = b[len(b)-1]
	if p.Type == TypeSyn || p.Type == TypeConnect {
		if len(body) < off+4 {
			return nil, errors.New("short SYN/CONNECT")
		}
		p.ConnSig = binary.LittleEndian.Uint32(body[off:])
		off += 4
	}
	if p.Type == TypeData {
		if len(body) < off+1 {
			return nil, errors.New("short DATA")
		}
		p.Fragment = body[off]
		off++
	}
	if p.Flags&FlagHasSize != 0 {
		if len(body) < off+2 {
			return nil, errors.New("short size field")
		}
		n := int(binary.LittleEndian.Uint16(body[off:]))
		off += 2
		if off+n > len(body) {
			return nil, fmt.Errorf("size field %d exceeds packet", n)
		}
		p.Payload = body[off : off+n]
	} else {
		p.Payload = body[off:]
	}
	return p, nil
}

func (p *Packet) Encode(l Layout, keySum byte) []byte {
	var w bytes.Buffer
	w.WriteByte(p.Src)
	w.WriteByte(p.Dst)
	w.WriteByte(l.join(p.Type, p.Flags))
	w.WriteByte(p.Session)
	binary.Write(&w, binary.LittleEndian, p.Signature)
	binary.Write(&w, binary.LittleEndian, p.Seq)
	if p.Type == TypeSyn || p.Type == TypeConnect {
		binary.Write(&w, binary.LittleEndian, p.ConnSig)
	}
	if p.Type == TypeData {
		w.WriteByte(p.Fragment)
	}
	if p.Flags&FlagHasSize != 0 {
		binary.Write(&w, binary.LittleEndian, uint16(len(p.Payload)))
	}
	w.Write(p.Payload)
	out := w.Bytes()
	return append(out, Checksum(out, keySum))
}

// Checksum is the Quazal v0 packet checksum: the byte sum of the access key,
// plus the bytes of the 32-bit word sum, plus any trailing bytes.
func Checksum(data []byte, keySum byte) byte {
	n := len(data) &^ 3
	var words uint32
	for i := 0; i < n; i += 4 {
		words += binary.LittleEndian.Uint32(data[i:])
	}
	sum := uint32(keySum)
	for _, c := range data[n:] {
		sum += uint32(c)
	}
	sum += words&0xff + words>>8&0xff + words>>16&0xff + words>>24
	return byte(sum)
}

func KeySum(accessKey string) byte {
	var s byte
	for i := 0; i < len(accessKey); i++ {
		s += accessKey[i]
	}
	return s
}

// Codec encodes and decodes packet payloads: optional per-packet RC4,
// then an optional leading compression byte (0 = stored, else zlib).
type Codec struct {
	RC4Key      []byte
	Compression bool
}

func (c Codec) String() string {
	enc := "plain"
	if c.RC4Key != nil {
		enc = fmt.Sprintf("rc4(%q)", c.RC4Key)
	}
	return fmt.Sprintf("%s, compression-byte=%v", enc, c.Compression)
}

func RC4(key, data []byte) []byte {
	ci, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(data))
	ci.XORKeyStream(out, data)
	return out
}

func (c Codec) Decode(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if c.RC4Key != nil {
		b = RC4(c.RC4Key, b)
	}
	if !c.Compression {
		return b, nil
	}
	if b[0] == 0 {
		return b[1:], nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(b[1:]))
	if err != nil {
		return nil, fmt.Errorf("zlib: %w", err)
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func (c Codec) Encode(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	if c.Compression {
		b = append([]byte{0}, b...)
	}
	if c.RC4Key != nil {
		b = RC4(c.RC4Key, b)
	}
	return b
}

// LooksLikeRMC reports whether b is a complete RMC message (u32 size prefix
// equal to the remaining length, followed by a protocol byte).
func LooksLikeRMC(b []byte) bool {
	return len(b) >= 9 && int(binary.LittleEndian.Uint32(b)) == len(b)-4
}

// DetectCodec tries the known payload encodings against one DATA payload
// and returns the first that yields a well-formed RMC message.
func DetectCodec(payload []byte) (Codec, bool) {
	for _, c := range []Codec{
		{RC4Key: []byte("CD&ML"), Compression: true},
		{RC4Key: []byte("CD&ML"), Compression: false},
		{Compression: true},
		{Compression: false},
	} {
		if d, err := c.Decode(payload); err == nil && LooksLikeRMC(d) {
			return c, true
		}
	}
	return Codec{}, false
}
