package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// --- Primitives ---

// ReadVarInt reads a VarInt.
func ReadVarInt(r io.ByteReader) (int, error) {
	var numRead int
	var result int
	for {
		read, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value := int(read & 0x7F)
		result |= value << (7 * numRead)

		numRead++
		if numRead > 5 {
			return 0, errors.New("varint is too big")
		}

		if (read & 0x80) == 0 {
			break
		}
	}
	return result, nil
}

// WriteVarInt writes a VarInt.
func WriteVarInt(w io.Writer, value int) error {
	for {
		temp := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}
		if _, err := w.Write([]byte{temp}); err != nil {
			return err
		}
		if value == 0 {
			break
		}
	}
	return nil
}

// WriteString writes a string as [Len][Bytes].
func WriteString(w io.Writer, s string) error {
	b := []byte(s)
	if err := WriteVarInt(w, len(b)); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// ReadString reads a string as [Len][Bytes].
func ReadString(r io.Reader) (string, error) {
	// ReadVarInt needs a ByteReader. If r doesn't implement it, wrap it
	// (slower, but works for simple readers - better to pass a bufio.Reader).
	var br io.ByteReader
	if b, ok := r.(io.ByteReader); ok {
		br = b
	} else {
		buf := make([]byte, 1)
		br = &byteReaderAdapter{r: r, buf: buf}
	}

	length, err := ReadVarInt(br)
	if err != nil {
		return "", err
	}

	// Guard against OOM on a malformed/hostile length prefix.
	if length > 32773 {
		return "", errors.New("string too long")
	}

	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return "", err
	}
	return string(out), nil
}

// byteReaderAdapter adapts a plain io.Reader to io.ByteReader.
type byteReaderAdapter struct {
	r   io.Reader
	buf []byte
}

func (b *byteReaderAdapter) ReadByte() (byte, error) {
	_, err := b.r.Read(b.buf)
	return b.buf[0], err
}

// --- Minecraft Types ---

func WriteBool(w io.Writer, b bool) {
	var v byte
	if b {
		v = 0x01
	}
	w.Write([]byte{v})
}

func WriteByte(w io.Writer, b byte) {
	w.Write([]byte{b})
}

func WriteLong(w io.Writer, v int64) {
	binary.Write(w, binary.BigEndian, v)
}

func WriteInt(w io.Writer, v int32) {
	binary.Write(w, binary.BigEndian, v)
}

func WriteFloat(w io.Writer, v float32) {
	binary.Write(w, binary.BigEndian, v)
}

func WriteDouble(w io.Writer, v float64) {
	binary.Write(w, binary.BigEndian, v)
}

// WritePacket assembles a packet as [Length][ID][Data] and sends it with a
// single Write.
//
// libXray patch: upstream wrote the length VarInt byte by byte and the body
// separately. Tunnel data and the background noise share one connection, so
// a frame split over several writes could interleave with another frame and
// desync the server; with Nagle disabled every byte of the length also left
// as its own one-byte TCP segment, which no Minecraft client sends.
func WritePacket(w io.Writer, packetID int, data []byte) error {
	packetBuffer := new(bytes.Buffer)
	WriteVarInt(packetBuffer, packetID)
	packetBuffer.Write(data)

	frame := new(bytes.Buffer)
	frame.Grow(packetBuffer.Len() + 5)
	WriteVarInt(frame, packetBuffer.Len())
	frame.Write(packetBuffer.Bytes())
	_, err := w.Write(frame.Bytes())
	return err
}

// frameWriter serializes whole frames from several goroutines onto one
// connection (libXray patch).
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (f *frameWriter) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.Write(b)
}
