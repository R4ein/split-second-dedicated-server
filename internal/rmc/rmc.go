// Package rmc implements Quazal Remote Method Call framing and the basic
// DDL data types (strings, buffers, lists, station URLs, ...).
package rmc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Message is one RMC request or response.
type Message struct {
	Request bool
	Proto   uint16
	CallID  uint32
	Method  uint32 // without the 0x8000 response bit
	OK      bool   // responses only
	Error   uint32 // responses only, when !OK
	Body    []byte
}

func Parse(b []byte) (*Message, error) {
	r := NewReader(b)
	size := r.U32()
	if int(size) != len(b)-4 {
		return nil, fmt.Errorf("rmc size %d != %d", size, len(b)-4)
	}
	m := &Message{}
	p := r.U8()
	m.Request = p&0x80 != 0
	m.Proto = uint16(p & 0x7f)
	if m.Proto == 0x7f {
		m.Proto = r.U16()
	}
	if m.Request {
		m.CallID = r.U32()
		m.Method = r.U32()
	} else {
		m.OK = r.U8() == 1
		if m.OK {
			m.CallID = r.U32()
			m.Method = r.U32() &^ 0x8000
		} else {
			m.Error = r.U32()
			m.CallID = r.U32()
		}
	}
	if r.Err() != nil {
		return nil, r.Err()
	}
	m.Body = r.Rest()
	return m, nil
}

func header(w *Writer, proto uint16, request bool) {
	flag := uint8(0)
	if request {
		flag = 0x80
	}
	if proto < 0x7f {
		w.U8(uint8(proto) | flag)
	} else {
		w.U8(0x7f | flag)
		w.U16(proto)
	}
}

func frame(w *Writer) []byte {
	out := make([]byte, 4, 4+w.Len())
	binary.LittleEndian.PutUint32(out, uint32(w.Len()))
	return append(out, w.Bytes()...)
}

func Response(proto uint16, callID, method uint32, body []byte) []byte {
	w := &Writer{}
	header(w, proto, false)
	w.U8(1)
	w.U32(callID)
	w.U32(method | 0x8000)
	w.Write(body)
	return frame(w)
}

func ErrorResponse(proto uint16, callID, code uint32) []byte {
	w := &Writer{}
	header(w, proto, false)
	w.U8(0)
	w.U32(code)
	w.U32(callID)
	return frame(w)
}

func Request(proto uint16, callID, method uint32, body []byte) []byte {
	w := &Writer{}
	header(w, proto, true)
	w.U32(callID)
	w.U32(method)
	w.Write(body)
	return frame(w)
}

// Quazal result / error codes.
const (
	ResultSuccess uint32 = 0x00010001

	ErrCoreUnknown        uint32 = 0x80010001
	ErrCoreNotImplemented uint32 = 0x80010002
	ErrCoreInvalidArg     uint32 = 0x8001000A
	ErrCoreAccessDenied   uint32 = 0x8001000C

	ErrRVConnectionFailure  uint32 = 0x80030001
	ErrRVNotAuthenticated   uint32 = 0x80030002
	ErrRVInvalidUsername    uint32 = 0x80030064
	ErrRVInvalidPassword    uint32 = 0x80030065
	ErrRVUsernameExists     uint32 = 0x80030066
	ErrRVAccountDisabled    uint32 = 0x80030067
	ErrRVConcurrentLogin    uint32 = 0x80030069
	ErrRVEncryptionFailure  uint32 = 0x8003006A
	ErrRVInvalidPID         uint32 = 0x8003006B
	ErrRVPermissionDenied   uint32 = 0x8003006F
	ErrRVInvalidGatheringID uint32 = 0x8003006D
)

// Writer serializes Quazal DDL types (little endian).
type Writer struct{ buf bytes.Buffer }

func (w *Writer) Write(b []byte) (int, error) { return w.buf.Write(b) }
func (w *Writer) WriteByte(c byte) error      { return w.buf.WriteByte(c) }
func (w *Writer) WriteString(s string)        { w.buf.WriteString(s) }
func (w *Writer) Bytes() []byte               { return w.buf.Bytes() }
func (w *Writer) Len() int                    { return w.buf.Len() }

func (w *Writer) U8(v uint8)   { w.WriteByte(v) }
func (w *Writer) U16(v uint16) { binary.Write(w, binary.LittleEndian, v) }
func (w *Writer) U32(v uint32) { binary.Write(w, binary.LittleEndian, v) }
func (w *Writer) U64(v uint64) { binary.Write(w, binary.LittleEndian, v) }
func (w *Writer) I32(v int32)  { binary.Write(w, binary.LittleEndian, v) }
func (w *Writer) F32(v float32) {
	binary.Write(w, binary.LittleEndian, v)
}
func (w *Writer) Bool(v bool) {
	if v {
		w.U8(1)
	} else {
		w.U8(0)
	}
}

// String is a u16 length (including the NUL) followed by the bytes and NUL.
func (w *Writer) String(s string) {
	w.U16(uint16(len(s) + 1))
	w.WriteString(s)
	w.WriteByte(0)
}

// Buffer is a u32 length followed by the bytes.
func (w *Writer) Buffer(b []byte) {
	w.U32(uint32(len(b)))
	w.Write(b)
}

// QBuffer is a u16 length followed by the bytes.
func (w *Writer) QBuffer(b []byte) {
	w.U16(uint16(len(b)))
	w.Write(b)
}

func (w *Writer) StringList(l []string) {
	w.U32(uint32(len(l)))
	for _, s := range l {
		w.String(s)
	}
}

func (w *Writer) U32List(l []uint32) {
	w.U32(uint32(len(l)))
	for _, v := range l {
		w.U32(v)
	}
}

// Reader deserializes Quazal DDL types. Errors are sticky.
type Reader struct {
	b   []byte
	off int
	err error
}

func NewReader(b []byte) *Reader { return &Reader{b: b} }

func (r *Reader) Err() error     { return r.err }
func (r *Reader) Remaining() int { return len(r.b) - r.off }
func (r *Reader) Rest() []byte {
	if r.off >= len(r.b) {
		return nil
	}
	out := r.b[r.off:]
	r.off = len(r.b)
	return out
}

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return make([]byte, n)
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = errors.New("rmc: read past end of message")
		return make([]byte, max(n, 0))
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *Reader) U8() uint8   { return r.take(1)[0] }
func (r *Reader) U16() uint16 { return binary.LittleEndian.Uint16(r.take(2)) }
func (r *Reader) U32() uint32 { return binary.LittleEndian.Uint32(r.take(4)) }
func (r *Reader) U64() uint64 { return binary.LittleEndian.Uint64(r.take(8)) }
func (r *Reader) Bool() bool  { return r.U8() != 0 }

func (r *Reader) String() string {
	n := int(r.U16())
	b := r.take(n)
	return string(bytes.TrimRight(b, "\x00"))
}

func (r *Reader) Buffer() []byte  { return append([]byte(nil), r.take(int(r.U32()))...) }
func (r *Reader) QBuffer() []byte { return append([]byte(nil), r.take(int(r.U16()))...) }

func (r *Reader) StringList() []string {
	n := r.U32()
	if n > 10000 {
		r.err = errors.New("rmc: list too long")
		return nil
	}
	out := make([]string, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		out = append(out, r.String())
	}
	return out
}

func (r *Reader) U32List() []uint32 {
	n := r.U32()
	if n > 100000 {
		r.err = errors.New("rmc: list too long")
		return nil
	}
	out := make([]uint32, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		out = append(out, r.U32())
	}
	return out
}
