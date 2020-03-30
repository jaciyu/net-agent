package socks5x

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Context socks5 context interface
type Context interface {
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	Close() error

	Username() string
	Password() string
	Command() int
	TargetAddr() net.Addr

	BindConn(net.Conn)
}

// context 连接上下文信息
type context struct {
	created        time.Time
	conn           net.Conn
	sourceAddr     string
	methods        []uint8
	methodSelected uint8
	username       string
	password       string
	command        uint8
	targetAddr     net.Addr
	targetConn     net.Conn

	isAuthed bool
}

func newContext(client net.Conn) *context {
	return &context{
		conn:    client,
		created: time.Now(),
	}
}

func (ctx *context) ReadStruct(st interface{}) error {
	return nil
}

func (ctx *context) RemoteAddr() net.Addr {
	return nil
}
func (ctx *context) LocalAddr() net.Addr {
	return nil
}
func (ctx *context) Close() error {
	return nil
}
func (ctx *context) Username() string {
	return "nil"
}
func (ctx *context) Password() string {
	return "nil"
}
func (ctx *context) Command() int {
	return 0
}
func (ctx *context) TargetAddr() net.Addr {
	return nil
}
func (ctx *context) BindConn(conn net.Conn) {}

type addr struct {
	addrType  uint8
	bufIPv4   []byte
	bufIPv6   []byte
	bufDomain []byte
	port      uint16

	str     string
	onceStr sync.Once

	buf     []byte
	onceBuf sync.Once
}

func newIPv4Addr(ip []byte, port uint16) *addr {
	p := &addr{
		addrType: IPv4,
		bufIPv4:  make([]byte, net.IPv4len),
		port:     port,
	}
	copy(p.bufIPv4, ip)
	return p
}

func newIPv6Addr(ip []byte, port uint16) *addr {
	p := &addr{
		addrType: IPv6,
		bufIPv6:  make([]byte, net.IPv6len),
		port:     port,
	}
	copy(p.bufIPv6, ip)
	return p
}

func newDomainAddr(domain []byte, port uint16) *addr {
	if len(domain) > 255 {
		domain = domain[0:255]
	}
	p := &addr{
		addrType:  Domain,
		bufDomain: make([]byte, len(domain)),
		port:      port,
	}
	copy(p.bufDomain, domain)
	return p
}

func (p *addr) Network() string {
	return "tcp4"
}

func (p *addr) String() string {
	p.onceStr.Do(func() {
		host := ""
		switch p.addrType {
		case IPv4:
			host = net.IP(p.bufIPv4).String()
		case IPv6:
			host = net.IP(p.bufIPv6).String()
		case Domain:
			host = string(p.bufDomain)
		}
		p.str = fmt.Sprintf("%v:%v", host, p.port)
	})
	return p.str
}

func (p *addr) Buffer() []byte {
	p.onceBuf.Do(func() {
		buf := []byte{p.addrType}
		switch p.addrType {
		case IPv4:
			buf = append(buf, p.bufIPv4...)
		case IPv6:
			buf = append(buf, p.bufIPv6...)
		case Domain:
			buf = append(buf, uint8(len(p.bufDomain)))
			buf = append(buf, p.bufDomain...)
		}
		p.buf = buf
	})
	return p.buf
}
