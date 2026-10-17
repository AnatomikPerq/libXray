package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
)

// --- SOCKS5 Handler ---
func (e *Engine) handleSocks(localConn net.Conn) {
	defer localConn.Close()
	buf := make([]byte, 256)

	// Handshake
	if _, err := io.ReadFull(localConn, buf[:2]); err != nil {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(localConn, buf[:nMethods]); err != nil {
		return
	}
	localConn.Write([]byte{0x05, 0x00}) // No auth

	// Request
	if _, err := io.ReadFull(localConn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 {
		return
	} // Only CONNECT supported

	var targetAddr string
	switch buf[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		io.ReadFull(localConn, ip)
		targetAddr = net.IP(ip).String()
	case 0x03: // Domain
		l := make([]byte, 1)
		io.ReadFull(localConn, l)
		domain := make([]byte, int(l[0]))
		io.ReadFull(localConn, domain)
		targetAddr = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		io.ReadFull(localConn, ip)
		targetAddr = net.IP(ip).String()
	}

	portBuf := make([]byte, 2)
	io.ReadFull(localConn, portBuf)
	port := binary.BigEndian.Uint16(portBuf)
	fullDest := fmt.Sprintf("%s:%d", targetAddr, port)

	e.proxyToTunnel(localConn, fullDest, true)
}

// --- HTTP Handler ---
func (e *Engine) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// HTTPS / TCP Tunneling via CONNECT
		dest := r.Host
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		// Send 200 OK to tell the client the tunnel is ready
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		e.proxyToTunnel(clientConn, dest, false) // false = no SOCKS reply needed
	} else {
		// Plain HTTP Proxying (Simplified)
		// For MVP we only support CONNECT for system-wide proxy usage mostly
		http.Error(w, "only CONNECT method supported in this MVP", http.StatusMethodNotAllowed)
	}
}

// --- Common Logic ---
func (e *Engine) proxyToTunnel(localConn net.Conn, dest string, isSocks bool) {
	sess := e.getSession()

	if sess == nil {
		if isSocks {
			localConn.Write([]byte{0x05, 0x01, 0, 1, 0, 0, 0, 0, 0, 0}) // Failure
		}
		e.log.Debugf("dropped connection to %s: no active tunnel session", dest)
		return
	}

	stream, err := sess.Open()
	if err != nil {
		e.log.Warnf("failed to open stream for %s: %v", dest, err)
		return
	}
	defer stream.Close()

	// Send destination to server
	destBuf := new(bytes.Buffer)
	WriteString(destBuf, dest)
	stream.Write(destBuf.Bytes())

	if isSocks {
		// SOCKS Success Reply
		localConn.Write([]byte{0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0})
	}

	// Pipe data
	go io.Copy(stream, localConn)
	io.Copy(localConn, stream)
}
