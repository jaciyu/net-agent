package socks5x

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	log "github.com/GZShi/net-agent/logger"
)

// Server socks5 server instant
type Server struct {
	listener           net.Listener
	supportAuthMethods []byte
	onAuthMaps         map[uint8]func(Context) error
	onCommandMaps      map[uint8]func(Context) error
}

// New 创建新的server
func New() *Server {
	return &Server{}
}

// Run 运行
func (p *Server) Run(listener net.Listener) {
	if listener == nil {
		log.Get().Error("listener is nil")
		return
	}
	p.listener = listener
	var wg sync.WaitGroup
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Get().WithError(err).Error("accept failed, stop listen")
			listener.Close()
			break
		}

		wg.Add(1)
		go func(client net.Conn) {
			defer wg.Done()
			p.handleClient(client)
		}(client)
	}

	log.Get().Info("wait all thread done...")
	wg.Wait()
}

// Stop 停止运行
func (p *Server) Stop() {
	if p.listener == nil {
		return
	}
	p.listener.Close()
}

func (p *Server) handleClient(client net.Conn) {
	ctx := newContext(client)
	defer ctx.Close()

	_, err := p.recvMethodList(ctx)
	if err != nil {
		log.Get().WithError(err).Error("recv method list failed")
		return
	}

	_, err = p.selectAuthMethod(ctx)
	if err != nil {
		log.Get().WithError(err).Error("select auth method failed")
		return
	}

	if err = p.sendSelectedMethod(ctx); err != nil {
		log.Get().WithError(err).Error("send selected method failed")
		return
	}

	err = p.doAuth(ctx)
	if err != nil {
		log.Get().WithError(err).Error("do auth failed")
		return
	}

	_, _, err = p.recvRequest(ctx)
	if err != nil {
		log.Get().WithError(err).Error("parse command failed")
		return
	}

	err = p.doCommand(ctx)
	if err != nil {
		log.Get().WithError(err).Error("do command failed")
		return
	}

	// work finished
}

func (p *Server) recvMethodList(ctx *context) (methods []uint8, err error) {
	buf := make([]byte, 1+1+255)
	rn, err := io.ReadAtLeast(ctx.conn, buf, 2)
	if err != nil {
		return nil, err
	}
	if rn <= 2 {
		return nil, errors.New("handshaking package is too small")
	}
	if buf[0] != Socks5Flag {
		return nil, errors.New("invalid protocol version")
	}
	nmethod := int(buf[1])
	if nmethod < 1 {
		return nil, errors.New("nmethod small than 1")
	}
	lostDataSize := nmethod + 2 - rn
	if lostDataSize < 0 {
		return nil, errors.New("package is too large")
	}
	if lostDataSize > 0 {
		fullDataSize := rn + lostDataSize
		_, err = io.ReadFull(ctx.conn, buf[rn:fullDataSize])
		if err != nil {
			return nil, err
		}
		rn = fullDataSize
	}
	copy(ctx.methods, buf[2:rn])
	return ctx.methods, nil
}

func (p *Server) selectAuthMethod(ctx *context) (method uint8, err error) {
	for _, supported := range p.supportAuthMethods {
		for _, method := range ctx.methods {
			if method == supported {
				ctx.methodSelected = method
				return method, nil
			}
		}
	}
	ctx.methodSelected = MethodNoAcceptable
	return MethodNoAcceptable, errors.New("no acceptable methods")
}

func (p *Server) sendSelectedMethod(ctx *context) (err error) {
	if ctx == nil || ctx.conn == nil {
		return errors.New("invalid context")
	}
	_, err = ctx.conn.Write([]byte{Socks5Flag, ctx.methodSelected})
	return
}

func (p *Server) doAuth(ctx *context) (err error) {
	if ctx.methodSelected == MethodNoAuthenticationRequired {
		return nil
	}

	fn, has := p.onAuthMaps[ctx.methodSelected]
	if !has {
		return errors.New("unsupported auth method")
	}

	return fn(ctx)
	// // methodSelected 正常流程下应该是支持的认证方式
	// switch ctx.methodSelected {
	// case MethodNoAuthenticationRequired:
	// 	// do nothing
	// 	return nil
	// case MethodUsernamePassword:
	// 	// recv username/password
	// 	if _, _, err := p.recvUsernamePassword(ctx); err != nil {
	// 		return err
	// 	}
	// 	if err = p.onAuthPassword(ctx); err != nil {
	// 		return err
	// 	}
	// 	return p.sendAuthResult(ctx)
	// default:
	// 	return errors.New("unsupported auth method")
	// }
}

func (p *Server) sendAuthResult(ctx *context) (err error) {
	if ctx == nil || ctx.conn == nil {
		return errors.New("invalid context")
	}
	if ctx.isAuthed {
		_, err = ctx.conn.Write([]byte{PasswordFlag, 0x00})
	} else {
		_, err = ctx.conn.Write([]byte{PasswordFlag, 0xff})
	}
	return
}

func (p *Server) recvUsernamePassword(ctx *context) (username, password string, err error) {
	buf := make([]byte, 1+1+255+1+255)
	rn, err := io.ReadAtLeast(ctx.conn, buf, 1+1)
	if err != nil {
		return "", "", err
	}
	if buf[0] != PasswordFlag {
		return "", "", errors.New("invalid package flag")
	}
	usernameSize := int(buf[1])
	lostDataSize := 1 + 1 + usernameSize + 1 - rn
	if lostDataSize > 0 {
		rn2, err := io.ReadAtLeast(ctx.conn, buf[rn:], lostDataSize)
		if err != nil {
			return "", "", err
		}
		rn += rn2
	}
	passwordSize := int(buf[1+1+usernameSize])
	lostDataSize = 1 + 1 + usernameSize + 1 + passwordSize - rn
	if lostDataSize < 0 {
		return "", "", errors.New("package is too large")
	}
	if lostDataSize < 0 {
		fullDataSize := rn + lostDataSize
		_, err := io.ReadFull(ctx.conn, buf[rn:fullDataSize])
		if err != nil {
			return "", "", err
		}
		rn = fullDataSize
	}

	username = string(buf[2 : 2+usernameSize])
	password = string(buf[2+usernameSize+1 : rn])
	ctx.username = username
	ctx.password = password

	return username, password, nil
}

func (p *Server) recvRequest(ctx *context) (command uint8, targetAddr net.Addr, err error) {
	// 	The SOCKS request is formed as follows:
	//
	// 	+----+-----+-------+------+----------+----------+
	// 	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// 	+----+-----+-------+------+----------+----------+
	// 	| 1  |  1  | X'00' |  1   | Variable |    2     |
	// 	+----+-----+-------+------+----------+----------+
	//
	// Where:
	//
	// 		o  VER    protocol version: X'05'
	// 		o  CMD
	// 			 o  CONNECT X'01'
	// 			 o  BIND X'02'
	// 			 o  UDP ASSOCIATE X'03'
	// 		o  RSV    RESERVED
	// 		o  ATYP   address type of following address
	// 			 o  IP V4 address: X'01'
	// 			 o  DOMAINNAME: X'03'
	// 			 o  IP V6 address: X'04'
	// 		o  DST.ADDR       desired destination address
	// 		o  DST.PORT desired destination port in network octet
	// 			 order
	buf := make([]byte, 4+1+255+2)
	rn, err := io.ReadAtLeast(ctx.conn, buf, 4+1+2)
	if err != nil {
		return
	}
	if buf[0] != Socks5Flag {
		err = errors.New("invalid protocol version")
		return
	}
	command = buf[1]
	ctx.command = command

	fullDataSize := 0
	switch buf[3] {
	case IPv4:
		fullDataSize = (4 + net.IPv4len + 2)
	case IPv6:
		fullDataSize = (4 + net.IPv6len + 2)
	case Domain:
		fullDataSize = (4 + 1 + int(buf[4]) + 2)
	default:
		err = errors.New("address type not supported")
		return
	}

	lostDataSize := fullDataSize - rn
	if lostDataSize < 0 {
		err = errors.New("package is too large")
		return
	}
	if lostDataSize > 0 {
		_, err = io.ReadFull(ctx.conn, buf[rn:fullDataSize])
		if err != nil {
			return
		}
	}
	rn = fullDataSize

	port := binary.BigEndian.Uint16(buf[fullDataSize-2 : fullDataSize])

	switch buf[3] {
	case IPv4:
		targetAddr = newIPv4Addr(buf[4:4+net.IPv4len], port)
	case IPv6:
		targetAddr = newIPv6Addr(buf[4:4+net.IPv6len], port)
	case Domain:
		targetAddr = newDomainAddr(buf[5:fullDataSize-2], port)
	default:
		err = errors.New("address type not supported")
		return
	}
	ctx.targetAddr = targetAddr

	err = nil
	return
}

func (p *Server) doCommand(ctx *context) (err error) {
	fn, has := p.onCommandMaps[ctx.command]
	if !has {
		return errors.New("command not supported")
	}

	return fn(ctx)
}

// OnAuth 注册认证方法
func (p *Server) OnAuth(authType uint8, fn func(Context) error) {
	if authType == MethodUsernamePassword {
		p.onAuthMaps[authType] = func(ctx Context) error {
			if _, _, err := p.recvUsernamePassword(ctx.(*context)); err != nil {
				return err
			}
			if err := fn(ctx); err != nil {
				return err
			}
			return p.sendAuthResult(ctx.(*context))
		}
		return
	}
	p.onAuthMaps[authType] = fn
}

// OnCommand 注册指令
func (p *Server) OnCommand(cmdType uint8, fn func(Context) error) {
	if cmdType == CommandConnect {
		p.onCommandMaps[cmdType] = fn
		return
	}
	log.Get().WithField("command", cmdType).Warn("command not supported")
}
