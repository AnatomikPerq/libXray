package core

import (
	"bufio"
	"bytes"
	"io"
	"sync"
	"testing"
)

// libXray patch tests.

type countingWriter struct {
	writes int
	buf    bytes.Buffer
}

func (c *countingWriter) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

func TestWritePacketIsOneWrite(t *testing.T) {
	w := &countingWriter{}
	payload := bytes.Repeat([]byte{0xAB}, 300) // two-byte length VarInt
	if err := WritePacket(w, pidSBPluginMsg, payload); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("frame took %d writes", w.writes)
	}
	r := bufio.NewReader(&w.buf)
	length, err := ReadVarInt(r)
	if err != nil || length != 301 {
		t.Fatalf("length = %d, %v", length, err)
	}
	if pid, _ := ReadVarInt(r); pid != pidSBPluginMsg {
		t.Fatalf("packet id = %#x", pid)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, payload) {
		t.Fatal("payload changed")
	}
}

// Frames written from many goroutines at once must arrive whole: tunnel
// data and the background noise share one connection.
func TestConcurrentFramesStayWhole(t *testing.T) {
	server, client := io.Pipe()
	out := &frameWriter{w: client}
	const writers, frames = 8, 200
	var wg sync.WaitGroup
	for id := 0; id < writers; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := bytes.Repeat([]byte{byte(id)}, 100+id*50)
			for i := 0; i < frames; i++ {
				if err := WritePacket(out, id, payload); err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}
	go func() {
		wg.Wait()
		client.Close()
	}()

	r := bufio.NewReader(server)
	seen := 0
	for {
		length, err := ReadVarInt(r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frame := make([]byte, length)
		if _, err := io.ReadFull(r, frame); err != nil {
			t.Fatal(err)
		}
		body := bytes.NewBuffer(frame)
		id, _ := ReadVarInt(body)
		if body.Len() != 100+id*50 || bytes.Count(body.Bytes(), []byte{byte(id)}) != body.Len() {
			t.Fatalf("frame %d of writer %d is mixed", seen, id)
		}
		seen++
	}
	if seen != writers*frames {
		t.Fatalf("got %d frames, want %d", seen, writers*frames)
	}
}
