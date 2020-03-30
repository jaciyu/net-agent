package socks5x

const (
	Socks5Flag   = uint8(0x05)
	PasswordFlag = uint8(0x01)

	MethodNoAuthenticationRequired = uint8(0x00)
	MethodGSSAPI                   = uint8(0x01)
	MethodUsernamePassword         = uint8(0x02)
	MethodNoAcceptable             = uint8(0xff)

	CommandConnect = uint8(0x01)
	CommandBind    = uint8(0x02)
	CommandUDP     = uint8(0x03)

	IPv4   = uint8(0x01)
	IPv6   = uint8(0x04)
	Domain = uint8(0x03)
)
