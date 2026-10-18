package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// --- PROTOCOL CONSTANTS --- (must stay in sync with the server)
const (
	protocolVersion     = 773 // 1.21.10
	pidSBHandshake      = 0x00
	pidSBLoginStart     = 0x00
	pidSBClientSettings = 0x08
	pidSBPluginMsg      = 0x0D
	pidSBPlayerPos      = 0x14
	pidSBKeepAlive      = 0x15

	pidCBKeepAlive = 0x24
	pidCBChunkData = 0x25
)

func (e *Engine) maintainSession() {
	backoff := 3 * time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		sess := e.getSession()
		needsConnect := sess == nil || sess.IsClosed()

		if needsConnect {
			s, err := e.connectToServer()
			if err == nil {
				e.setSession(s)
				e.setLastErr(nil)
				e.log.Infof("connected and logged in")
				backoff = 3 * time.Second // reset after a successful connect
			} else {
				e.setLastErr(err)
				e.log.Errorf("connect failed: %v (retrying in %s)", err, backoff)
				select {
				case <-e.ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				continue
			}
		}

		// libXray patch: react to a dropped session at once instead of on
		// the next 3 s poll; until then every new stream is refused.
		var closed <-chan struct{}
		if s := e.getSession(); s != nil {
			closed = s.CloseChan()
		}
		select {
		case <-e.ctx.Done():
			return
		case <-closed:
		case <-time.After(3 * time.Second):
		}
	}
}

func (e *Engine) connectToServer() (*yamux.Session, error) {
	// libXray patch: an injectable dialer, and Stop aborts a pending dial.
	dial := e.cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dialCtx, cancelDial := context.WithTimeout(e.ctx, 10*time.Second)
	conn, err := dial(dialCtx, "tcp", e.cfg.ServerAddress)
	cancelDial()
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true) // Disable Nagle
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// libXray patch: tunnel data and background noise write concurrently;
	// every frame goes through one serialized writer.
	out := &frameWriter{w: conn}

	// 1. Handshake
	h := sha256.Sum256([]byte(e.cfg.Password))
	username := "Player" + hex.EncodeToString(h[:])[:8]

	buf := new(bytes.Buffer)
	WriteVarInt(buf, protocolVersion)
	WriteString(buf, "127.0.0.1")
	buf.Write([]byte{0x63, 0xDD})
	WriteVarInt(buf, 2)
	WritePacket(out, pidSBHandshake, buf.Bytes())

	// 2. Login Start
	buf.Reset()
	WriteString(buf, username)
	WritePacket(out, pidSBLoginStart, buf.Bytes())

	// 3. Consume packets sent by the server before the tunnel starts.
	// The current server (handler.go/startDeepCoverSession) sends THREE
	// packets in a row after a successful login:
	//   1. Login Success   (0x02)
	//   2. Join Game       (0x29)
	//   3. Player Position (0x3E) - synchronizes the simulated spawn position
	// Older server versions only sent the first two, so this used to be 2.
	// If this count doesn't match what the server actually sends, the
	// leftover packet gets fed straight into the yamux reader as if it were
	// tunnel data, and the session desyncs immediately.
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	packetsToRead := 3
	for packetsToRead > 0 {
		l, err := ReadVarInt(reader)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(reader, make([]byte, l)); err != nil {
			conn.Close()
			return nil, err
		}
		packetsToRead--
	}
	conn.SetReadDeadline(time.Time{})

	// 4. Client Settings
	buf.Reset()
	WriteString(buf, "en_US")
	WriteByte(buf, 8)
	WriteVarInt(buf, 0)
	WriteBool(buf, true)
	WriteByte(buf, 0x7F)
	WriteVarInt(buf, 1)
	WriteBool(buf, false)
	WriteBool(buf, true)
	WritePacket(out, pidSBClientSettings, buf.Bytes())

	// 5. Setup Tunnel
	key := sha256.Sum256([]byte(e.cfg.Password))
	block, _ := aes.NewCipher(key[:])
	aead, _ := cipher.NewGCM(block)

	pr, pw := io.Pipe()
	mc := &minecraftConn{
		conn:      conn,
		out:       out,
		r:         pr,
		w:         pw,
		aead:      aead,
		rawReader: reader,
		bucket:    newThrottleBucket(e.cfg), // nil in fast mode - no throttling
	}

	go e.startBackgroundNoise(out)
	go e.startReaderLoop(mc, pw, conn, aead)

	conf := yamux.DefaultConfig()
	conf.KeepAliveInterval = 30 * time.Second
	conf.ConnectionWriteTimeout = 15 * time.Second
	conf.MaxStreamWindowSize = 16 * 1024 * 1024
	conf.StreamOpenTimeout = 30 * time.Second
	// libXray patch: yamux logs to the host's writer instead of stderr.
	if e.cfg.LogWriter != nil {
		conf.LogOutput = e.cfg.LogWriter
	}
	return yamux.Client(mc, conf)
}

func (e *Engine) startBackgroundNoise(conn io.Writer) {
	posTicker := time.NewTicker(1 * time.Second)
	kaTicker := time.NewTicker(5 * time.Second)
	defer posTicker.Stop()
	defer kaTicker.Stop()
	posX, posY, posZ := 100.5, 64.0, 100.5
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-posTicker.C:
			jitter := float64(time.Now().UnixNano()%100) / 5000.0
			b := new(bytes.Buffer)
			WriteDouble(b, posX+jitter)
			WriteDouble(b, posY)
			WriteDouble(b, posZ+jitter)
			WriteBool(b, true)
			if WritePacket(conn, pidSBPlayerPos, b.Bytes()) != nil {
				return
			}
		case <-kaTicker.C:
			e.kaLock.Lock()
			idToSend := e.lastKeepAliveID
			e.kaLock.Unlock()
			if idToSend != 0 {
				b := new(bytes.Buffer)
				WriteLong(b, idToSend)
				if WritePacket(conn, pidSBKeepAlive, b.Bytes()) != nil {
					return
				}
			}
		}
	}
}

func (e *Engine) startReaderLoop(mc *minecraftConn, pw *io.PipeWriter, conn net.Conn, aead cipher.AEAD) {
	// libXray patch: the NBT skipper indexes past short buffers on a
	// malformed frame. That has to end this session, not the host process
	// the engine runs in. Deferred first, so the closes below still run.
	defer func() {
		if r := recover(); r != nil {
			e.log.Errorf("tunnel reader: malformed frame: %v", r)
		}
	}()
	defer pw.Close()
	defer conn.Close()
	var r io.ByteReader
	if br, ok := mc.rawReader.(io.ByteReader); ok {
		r = br
	} else {
		r = bufio.NewReader(mc.rawReader)
	}

	for {
		l, err := ReadVarInt(r)
		if err != nil {
			return
		}
		if l < 0 || l > 2097152 {
			return
		}

		data := make([]byte, l)
		if _, err := io.ReadFull(mc.rawReader, data); err != nil {
			return
		}

		pBuf := bytes.NewBuffer(data)
		pid, _ := ReadVarInt(pBuf)

		if pid == pidCBChunkData {
			// Structure: X(4) + Z(4) + NBT(Heightmaps) + Size(VarInt) + Data
			if pBuf.Len() < 8 {
				continue
			}
			pBuf.Next(8) // Skip X, Z

			// --- SMART NBT SKIPPER ---
			// We must parse the NBT structure to skip it correctly
			if err := skipNBT(pBuf); err != nil {
				continue // Skip malformed packet
			}

			// Read Payload
			payloadSize, err := ReadVarInt(pBuf)
			if err != nil {
				continue
			}
			if pBuf.Len() < payloadSize {
				continue
			}

			enc := pBuf.Next(payloadSize)
			if len(enc) < aead.NonceSize() {
				continue
			}
			nonce := enc[:aead.NonceSize()]
			pt, err := aead.Open(nil, nonce, enc[aead.NonceSize():], nil)
			if err == nil {
				pw.Write(pt)
			}

		} else if pid == pidCBKeepAlive {
			var kId int64
			if pBuf.Len() >= 8 {
				binary.Read(pBuf, binary.BigEndian, &kId)
				e.kaLock.Lock()
				e.lastKeepAliveID = kId
				e.kaLock.Unlock()
			}
		}
		// Any other CB packet (e.g. Time Update) is intentionally ignored here -
		// it's just camouflage traffic from the server and carries no tunnel data.
	}
}

// Helper to recursively skip NBT tags
func skipNBT(r *bytes.Buffer) error {
	tagType, err := r.ReadByte() // Read Tag Type
	if err != nil {
		return err
	}

	if tagType == 0 {
		return nil
	} // TAG_End

	// Read Name (Short + Bytes) - Root compound usually has name (even empty)
	nameLen := int(binary.BigEndian.Uint16(r.Next(2)))
	r.Next(nameLen)

	return skipNBTPayload(r, tagType)
}

func skipNBTPayload(r *bytes.Buffer, tagType byte) error {
	switch tagType {
	case 1:
		r.Next(1) // Byte
	case 2:
		r.Next(2) // Short
	case 3:
		r.Next(4) // Int
	case 4:
		r.Next(8) // Long
	case 5:
		r.Next(4) // Float
	case 6:
		r.Next(8) // Double
	case 7: // Byte Array
		l := int(int32(binary.BigEndian.Uint32(r.Next(4))))
		r.Next(l)
	case 8: // String
		l := int(binary.BigEndian.Uint16(r.Next(2)))
		r.Next(l)
	case 9: // List
		subType, _ := r.ReadByte()
		l := int(int32(binary.BigEndian.Uint32(r.Next(4))))
		for i := 0; i < l; i++ {
			skipNBTPayload(r, subType)
		}
	case 10: // Compound
		for {
			subType, _ := r.ReadByte()
			if subType == 0 {
				break
			} // TAG_End
			nLen := int(binary.BigEndian.Uint16(r.Next(2)))
			r.Next(nLen)
			skipNBTPayload(r, subType)
		}
	case 11: // Int Array
		l := int(int32(binary.BigEndian.Uint32(r.Next(4))))
		r.Next(l * 4)
	case 12: // Long Array
		l := int(int32(binary.BigEndian.Uint32(r.Next(4))))
		r.Next(l * 8)
	}
	return nil
}

// minecraftConn wraps the raw TCP connection as a net.Conn that yamux can
// run over: writes get AES-GCM sealed and wrapped in a plugin-message
// packet (optionally throttled), reads come from the decrypted pipe fed by
// startReaderLoop.
type minecraftConn struct {
	conn      net.Conn
	out       io.Writer // serialized frames to conn
	r         *io.PipeReader
	w         *io.PipeWriter
	aead      cipher.AEAD
	rawReader io.Reader
	bucket    *tokenBucket // nil in fast mode; set in realistic mode
}

func (mc *minecraftConn) Read(b []byte) (int, error) { return mc.r.Read(b) }
func (mc *minecraftConn) Write(b []byte) (int, error) {
	// Throttle upload to match the server's throttled download in realistic
	// mode (no-op when mc.bucket is nil, i.e. fast mode).
	mc.bucket.WaitN(len(b))

	nonce := make([]byte, mc.aead.NonceSize())
	rand.Read(nonce)
	encrypted := mc.aead.Seal(nonce, nonce, b, nil)
	buf := new(bytes.Buffer)
	WriteString(buf, "minecraft:brand")
	buf.Write(encrypted)
	if err := WritePacket(mc.out, pidSBPluginMsg, buf.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}
func (mc *minecraftConn) Close() error                       { return mc.conn.Close() }
func (mc *minecraftConn) LocalAddr() net.Addr                { return mc.conn.LocalAddr() }
func (mc *minecraftConn) RemoteAddr() net.Addr               { return mc.conn.RemoteAddr() }
func (mc *minecraftConn) SetDeadline(t time.Time) error      { return mc.conn.SetDeadline(t) }
func (mc *minecraftConn) SetReadDeadline(t time.Time) error  { return mc.conn.SetReadDeadline(t) }
func (mc *minecraftConn) SetWriteDeadline(t time.Time) error { return mc.conn.SetWriteDeadline(t) }
