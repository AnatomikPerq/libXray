package netreport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/apernet/quic-go"
)

type UDPReport struct {
	STUN []STUNResult `json:"stun"`
	QUIC []QUICResult `json:"quic"`
	// SymmetricNAT is set when two STUN servers saw one socket on different
	// ports; peer-to-peer UDP (calls, games) then needs a relay.
	SymmetricNAT *bool `json:"symmetricNat,omitempty"`
}

type STUNResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	IP     string `json:"ip,omitempty"`
	Status Status `json:"status"`
	Ms     int64  `json:"ms,omitempty"`
	port   int
}

type QUICResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	IP   string `json:"ip,omitempty"`
	Step
}

func (p *prober) runUDP(ctx context.Context, report func(*UDPReport)) {
	result := &UDPReport{STUN: make([]STUNResult, len(p.cat.STUN)), QUIC: make([]QUICResult, len(p.cat.QUIC))}
	var wait sync.WaitGroup
	wait.Go(func() { p.runSTUN(ctx, result) })
	for index, entry := range p.cat.QUIC {
		wait.Go(func() {
			item := QUICResult{ID: entry.ID, Name: entry.Name, Host: entry.Host}
			addrs, _, err := p.lookup(ctx, entry.Host)
			if err != nil || len(addrs) == 0 {
				item.Step = Step{Status: StatusError, Detail: "unresolved"}
			} else {
				item.IP = addrs[0].String()
				item.Step = p.quicStep(ctx, addrs[0], entry.Host)
			}
			result.QUIC[index] = item
		})
	}
	wait.Wait()
	report(result)
}

// runSTUN asks every server from one socket, so the mapped ports compare.
func (p *prober) runSTUN(ctx context.Context, result *UDPReport) {
	conn, err := p.listenUDP(ctx, false)
	if err != nil {
		for index, entry := range p.cat.STUN {
			result.STUN[index] = STUNResult{ID: entry.ID, Name: entry.Name, Host: entry.Host, Status: StatusError}
		}
		return
	}
	defer conn.Close()
	ports := map[int]bool{}
	for index, entry := range p.cat.STUN {
		item := STUNResult{ID: entry.ID, Name: entry.Name, Host: entry.Host, Status: StatusTimeout}
		addrs, _, err := p.lookup(ctx, entry.Host)
		if err != nil || len(addrs) == 0 {
			item.Status = StatusError
			result.STUN[index] = item
			continue
		}
		item.IP = addrs[0].String()
		target := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addrs[0], uint16(entry.Port)))
		for attempt := 0; attempt < 2 && item.Status == StatusTimeout; attempt++ {
			start := time.Now()
			port, err := stunBinding(conn, target)
			if err == nil {
				item.Status, item.Ms, item.port = StatusOK, since(start), port
				ports[port] = true
			} else if classify(err) != StatusTimeout {
				item.Status = classify(err)
			}
		}
		result.STUN[index] = item
	}
	answered := 0
	for _, item := range result.STUN {
		if item.Status == StatusOK {
			answered++
		}
	}
	if answered >= 2 {
		symmetric := len(ports) > 1
		result.SymmetricNAT = &symmetric
	}
}

const stunMagic = 0x2112A442

// stunBinding sends a Binding request and returns the mapped port.
func stunBinding(conn net.PacketConn, target net.Addr) (int, error) {
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:], 0x0001)
	binary.BigEndian.PutUint32(request[4:], stunMagic)
	if _, err := rand.Read(request[8:20]); err != nil {
		return 0, err
	}
	if _, err := conn.WriteTo(request, target); err != nil {
		return 0, err
	}
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 1500)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			return 0, err
		}
		response := buffer[:n]
		if n < 20 || binary.BigEndian.Uint16(response[0:]) != 0x0101 || string(response[8:20]) != string(request[8:20]) {
			continue
		}
		return mappedPort(response)
	}
}

func mappedPort(response []byte) (int, error) {
	for offset := 20; offset+4 <= len(response); {
		kind := binary.BigEndian.Uint16(response[offset:])
		length := int(binary.BigEndian.Uint16(response[offset+2:]))
		value := response[offset+4 : min(offset+4+length, len(response))]
		if len(value) >= 4 {
			port := int(binary.BigEndian.Uint16(value[2:]))
			switch kind {
			case 0x0020: // XOR-MAPPED-ADDRESS
				return port ^ (stunMagic >> 16), nil
			case 0x0001: // MAPPED-ADDRESS
				return port, nil
			}
		}
		offset += 4 + (length+3)&^3
	}
	return 0, errors.New("no mapped address")
}

// quicStep runs a QUIC handshake (HTTP/3 ALPN) with the real name.
func (p *prober) quicStep(ctx context.Context, ip netip.Addr, host string) Step {
	conn, err := p.listenUDP(ctx, !ip.Is4())
	if err != nil {
		return Step{Status: StatusError, Detail: detail(err)}
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	start := time.Now()
	session, err := quic.Dial(ctx, conn, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 443)),
		&tls.Config{ServerName: host, NextProtos: []string{"h3"}},
		&quic.Config{HandshakeIdleTimeout: handshakeTimeout})
	step := Step{Status: classify(err), Ms: since(start)}
	if err != nil {
		step.Detail = detail(err)
		return step
	}
	_ = session.CloseWithError(0, "")
	return step
}
