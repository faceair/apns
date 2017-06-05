package apns

import (
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/proxy"
)

const (
	ProductionGateway = "gateway.push.apple.com:2195"
	SandboxGateway    = "gateway.sandbox.push.apple.com:2195"

	ProductionFeedbackGateway = "feedback.push.apple.com:2196"
	SandboxFeedbackGateway    = "feedback.sandbox.push.apple.com:2196"
)

// Conn is a wrapper for the actual TLS connections made to Apple
type Conn struct {
	NetConn net.Conn
	Conf    *tls.Config

	gateway   string
	connected bool
}

func NewConnWithCert(gw string, cert tls.Certificate) Conn {
	gatewayParts := strings.Split(gw, ":")
	conf := tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   gatewayParts[0],
	}

	return Conn{gateway: gw, Conf: &conf}
}

// NewConnWithFiles creates a new Conn from certificate and key in the specified files
func NewConn(gw string, crt string, key string) (Conn, error) {
	cert, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		return Conn{}, err
	}

	return NewConnWithCert(gw, cert), nil
}

// NewConnWithFiles creates a new Conn from certificate and key in the specified files
func NewConnWithFiles(gw string, certFile string, keyFile string) (Conn, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return Conn{}, err
	}

	return NewConnWithCert(gw, cert), nil
}

// Connect actually creates the TLS connection
func (c *Conn) Connect() error {
	// Make sure the existing connection is closed
	if c.NetConn != nil {
		c.NetConn.Close()
	}

	var useProxy bool
	var conn net.Conn
	var err error

	allProxy := os.Getenv("all_proxy")
	if len(allProxy) != 0 {
		proxyURL, err := url.Parse(allProxy)
		if err == nil {
			dialer, err := proxy.FromURL(proxyURL, &net.Dialer{})
			if err == nil {
				conn, _ = dialer.Dial("tcp", c.gateway)
				useProxy = true
			}
		}
	}
	if !useProxy {
		conn, err = net.Dial("tcp", c.gateway)
	}

	tlsConn := tls.Client(conn, c.Conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}

	c.NetConn = tlsConn
	return nil
}

func (c *Conn) Close() error {
	if c.NetConn != nil {
		return c.NetConn.Close()
	}

	return nil
}

// Read reads data from the connection
func (c *Conn) Read(p []byte) (int, error) {
	i, err := c.NetConn.Read(p)
	return i, err
}

// Write writes data from the connection
func (c *Conn) Write(p []byte) (int, error) {
	return c.NetConn.Write(p)
}
