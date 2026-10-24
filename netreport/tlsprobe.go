package netreport

import (
	"bytes"
	"context"
	"crypto/x509"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

type tlsOptions struct {
	// sni goes into the ClientHello; empty omits the extension.
	sni string
	// verify is the name the certificate must be valid for; empty skips the
	// check (a borrowed SNI never matches the server's certificate).
	verify string
	// split sends the ClientHello in two TCP segments cut inside the SNI.
	split bool
	// fragment sends it as the App's Fragment setting does (Xray freedom
	// "tlshello", 100-200 bytes, 10-20 ms): several TLS records, each in a
	// write of its own.
	fragment bool
}

// countingConn counts what the server sent, handshake included: the TSPU
// limit counts packets on the wire, not decrypted body bytes.
type countingConn struct {
	net.Conn
	rx       atomic.Int64
	split    bool
	fragment bool
	sni      string
	wrote    bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.rx.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	if !c.split && !c.fragment || c.wrote {
		return c.Conn.Write(b)
	}
	c.wrote = true
	if c.fragment {
		return c.writeRecords(b)
	}
	// The first write is the whole ClientHello record. Cut it in the
	// middle of the server name, so no single segment carries the name.
	cut := len(b) / 2
	if c.sni != "" {
		if index := bytes.Index(b, []byte(c.sni)); index > 0 {
			cut = index + len(c.sni)/2
		}
	}
	first, err := c.Conn.Write(b[:cut])
	if err != nil {
		return first, err
	}
	time.Sleep(30 * time.Millisecond)
	second, err := c.Conn.Write(b[cut:])
	return first + second, err
}

// writeRecords re-frames the ClientHello record into records of 100-200
// bytes of the same handshake message. Servers reassemble them; a DPI that
// reads only the first record or packet does not see the whole name.
func (c *countingConn) writeRecords(b []byte) (int, error) {
	if len(b) < 5 || b[0] != 0x16 {
		return c.Conn.Write(b)
	}
	length := int(b[3])<<8 | int(b[4])
	if 5+length > len(b) {
		return c.Conn.Write(b)
	}
	payload := b[5 : 5+length]
	for len(payload) > 0 {
		size := min(100+rand.IntN(101), len(payload))
		record := append([]byte{b[0], b[1], b[2], byte(size >> 8), byte(size)}, payload[:size]...)
		if _, err := c.Conn.Write(record); err != nil {
			return 0, err
		}
		payload = payload[size:]
		time.Sleep(time.Duration(10+rand.IntN(11)) * time.Millisecond)
	}
	if rest := b[5+length:]; len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// chromeSpec is Chrome's ClientHello with ALPN limited to HTTP/1.1, which
// the probes speak; the rest of the fingerprint stays Chrome's, as DPI rules
// are tuned to browsers.
func chromeSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		return spec, err
	}
	for _, extension := range spec.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	return spec, nil
}

type tlsConn struct {
	*utls.UConn
	counter *countingConn
}

// handshake connects and runs a TLS handshake, reporting the TCP and TLS
// steps separately. The connection is returned only when both succeed.
func (p *prober) handshake(ctx context.Context, ip netip.Addr, port int, options tlsOptions) (*tlsConn, Step, Step) {
	raw, tcp := p.dialTCP(ctx, ip, port)
	if raw == nil {
		return nil, tcp, Step{Status: StatusSkipped}
	}
	counter := &countingConn{Conn: raw, split: options.split, fragment: options.fragment, sni: options.sni}
	config := &utls.Config{
		ServerName:         options.sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	conn := utls.UClient(counter, config, utls.HelloCustom)
	spec, err := chromeSpec()
	if err == nil {
		err = conn.ApplyPreset(&spec)
	}
	if err != nil {
		raw.Close()
		return nil, tcp, Step{Status: StatusError, Detail: detail(err)}
	}
	start := time.Now()
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	err = conn.HandshakeContext(handshakeCtx)
	step := Step{Status: classify(err), Ms: since(start)}
	if err != nil {
		step.Detail = detail(err)
		raw.Close()
		return nil, tcp, step
	}
	if options.verify != "" {
		if err := verifyChain(conn.ConnectionState().PeerCertificates, options.verify); err != nil {
			step.Status = StatusCertInvalid
			step.Detail = detail(err)
		}
	}
	return &tlsConn{UConn: conn, counter: counter}, tcp, step
}

func verifyChain(certificates []*x509.Certificate, name string) error {
	if len(certificates) == 0 {
		return x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := certificates[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: intermediates})
	return err
}

// tlsFailure explains a failed handshake with the real name from the
// retries on the same address.
func tlsFailure(noSNI, random, white *Step) Status {
	switch {
	case random != nil && reached(random.Status):
		return StatusSNIBlocked
	case white != nil && reached(white.Status):
		return StatusSNIWhitelist
	case noSNI != nil && reached(noSNI.Status):
		return StatusNoSNIOnly
	}
	return StatusTLSBlocked
}

// tlsVariants retries a refused address without a name, with a made-up one
// and with an allowed one, at once and slightly apart. Different names keep
// the "Siberian" limit (several handshakes with one name) out of it.
func (p *prober) tlsVariants(ctx context.Context, ip netip.Addr, port int, white string) (noSNI, random, allowed *Step) {
	var wait sync.WaitGroup
	run := func(delay time.Duration, options tlsOptions, into **Step) {
		wait.Go(func() {
			select {
			case <-ctx.Done():
			case <-time.After(delay):
			}
			step := p.tlsStep(ctx, ip, port, options)
			*into = &step
		})
	}
	run(0, tlsOptions{}, &noSNI)
	run(120*time.Millisecond, tlsOptions{sni: randomHost()}, &random)
	if white != "" {
		run(240*time.Millisecond, tlsOptions{sni: white}, &allowed)
	}
	wait.Wait()
	return noSNI, random, allowed
}

// bypassSteps retries a refused name with the ClientHello split in two TCP
// segments and re-framed into small records, at once and slightly apart.
// A handshake that gets through goes on with the same request as the plain
// try: a filter may still cut or freeze the data after it.
func (p *prober) bypassSteps(ctx context.Context, ip netip.Addr, host string, request fetchOptions) (split, fragment *Step, transfer *Transfer) {
	var wait sync.WaitGroup
	wait.Go(func() {
		step := p.tlsStep(ctx, ip, 443, tlsOptions{sni: host, verify: host, split: true})
		split = &step
	})
	wait.Go(func() {
		select {
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
		conn, tcp, step := p.handshake(ctx, ip, 443, tlsOptions{sni: host, verify: host, fragment: true})
		if failed(tcp.Status) {
			step = Step{Status: tcp.Status, Ms: tcp.Ms, Detail: "tcp"}
		}
		fragment = &step
		if conn != nil {
			if step.Status == StatusOK {
				result := fetch(ctx, conn, conn.counter.rx.Load, request)
				transfer = &result
			}
			conn.Close()
		}
	})
	wait.Wait()
	return split, fragment, transfer
}

// bypassWorks: the cut-up hello got through and so did the data after it.
func bypassWorks(step *Step, transfer *Transfer) bool {
	return step != nil && reached(step.Status) && (transfer == nil || !failed(transfer.Status))
}

// tlsStep runs a handshake only for its outcome.
func (p *prober) tlsStep(ctx context.Context, ip netip.Addr, port int, options tlsOptions) Step {
	conn, tcp, step := p.handshake(ctx, ip, port, options)
	if conn != nil {
		conn.Close()
	}
	if failed(tcp.Status) {
		// The TCP step is the one that tells.
		return Step{Status: tcp.Status, Ms: tcp.Ms, Detail: "tcp"}
	}
	return step
}
