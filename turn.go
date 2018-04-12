package turn

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
)

const (
	ReadBufferLength = 1500
)

var (
	TransportUDP = []byte{0x11, 0x00, 0x00, 0x00}
)

var (
	ErrInvalidPacket = errors.New("invalid packet")
	errEntryNotFound = errors.New("entry not found")
)

type TwoBytesTree map[byte]map[byte]string

func (t TwoBytesTree) Find(v []byte) (string, error) {
	if len(v) != 2 {
		return "", errEntryNotFound
	}

	if _, ok := t[v[0]]; ok == false {
		return "", errEntryNotFound
	}
	if vt, ok := t[v[0]]; ok == false {
		return "", errEntryNotFound
	} else {
		return vt[v[1]], nil
	}
}

type Client struct {
	Username []byte
	Password []byte

	conn        *net.UDPConn
	addr        *net.UDPAddr
	readBuf     []byte
	readChan    chan []byte
	nonce       []byte
	realm       []byte
	authRequire bool
}

type DialOption func(*Client)

func WithLongTermCredential(username, password string) DialOption {
	return func(c *Client) {
		c.Username = []byte(username)
		c.Password = []byte(password)
	}
}

func Dial(addr string, opt ...DialOption) *Client {
	a, _ := net.ResolveUDPAddr("udp", ":")
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil
	}
	turnAddr, _ := net.ResolveUDPAddr("udp", addr)

	c := &Client{conn: conn, addr: turnAddr, readBuf: make([]byte, ReadBufferLength), readChan: make(chan []byte, 0)}
	for _, o := range opt {
		o(c)
	}
	return c
}

func (client *Client) Allocate() (net.IP, int, error) {
	attrs := Attributes([]Attribute{NewBaseAttribute(AttributeRequestedTransport, TransportUDP)})
	message := NewSTUNMessage(MethodAllocate)
	message.Body = attrs.Encode()
	buf := message.Encode()

	client.conn.WriteToUDP(buf, client.addr)

	n, err := client.conn.Read(client.readBuf)
	if err != nil {
		return nil, -1, err
	}
	res, err := ParseSTUNMessage(client.readBuf[:n])
	if err != nil {
		return nil, -1, err
	}
	resAttrs, err := res.Attributes()
	if err != nil {
		return nil, -1, err
	}
	for _, attr := range resAttrs {
		switch attr.Key().TypeString() {
		case AttributeNonce:
			client.nonce = attr.(BaseAttribute).RawValue
		case AttributeRealm:
			client.realm = attr.(BaseAttribute).RawValue
		}
	}
	if res.IsError() && STUNErrorMessage(*res).Code() == ErrorUnauthorized {
		return client.allocateWithAuthenticate()
	}
	if res.IsError() {
		return nil, -1, errors.New(STUNErrorMessage(*res).ErrorMessage())
	}

	var mappedAddress XorAddressAttribute
	for _, attr := range resAttrs {
		if attr.Key().TypeString() == AttributeXorMappedAddress {
			mappedAddress = attr.(XorAddressAttribute)
			break
		}
	}

	err = client.RefreshAllocation()
	if err != nil {
		return nil, -1, err
	}
	return mappedAddress.Address, mappedAddress.Port, nil
}

func (client *Client) RefreshAllocation() error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(600))
	attrs := Attributes([]Attribute{NewBaseAttribute(AttributeLifetime, buf)})
	if client.authRequire {
		attrs = append(attrs, NewBaseAttribute(AttributeUsername, []byte(client.Username)),
			NewBaseAttribute(AttributeRealm, client.realm),
			NewBaseAttribute(AttributeNonce, client.nonce))
	}
	message := NewSTUNMessage(MethodRefreshAllocation)
	message.Body = attrs.Encode()
	if client.authRequire {
		messageIntegrity := message.Authenticate(client.realm, client.Username, client.Password)
		attrs = append(attrs, NewBaseAttribute(AttributeMessageIntegrity, messageIntegrity))
		message.Body = attrs.Encode()
	}
	client.conn.WriteToUDP(message.Encode(), client.addr)

	n, err := client.conn.Read(client.readBuf)
	if err != nil {
		return nil
	}
	res, err := ParseSTUNMessage(client.readBuf[:n])
	if err != nil {
		return nil
	}
	if res.IsError() {
		return errors.New(STUNErrorMessage(*res).ErrorMessage())
	}

	return nil
}

func (client *Client) CreatePermission(peer net.IP) error {
	addr := NewXorAddressAttribute(AttributeXorPeerAddress)
	addr.Family = AddressFamilyV4
	addr.Address = peer

	attrs := Attributes([]Attribute{addr})
	if client.authRequire {
		attrs = append(attrs, NewBaseAttribute(AttributeUsername, []byte(client.Username)),
			NewBaseAttribute(AttributeRealm, client.realm),
			NewBaseAttribute(AttributeNonce, client.nonce))
	}
	message := NewSTUNMessage(MethodCreatePermission)
	message.Body = attrs.Encode()
	if client.authRequire {
		messageIntegrity := message.Authenticate(client.realm, client.Username, client.Password)
		attrs = append(attrs, NewBaseAttribute(AttributeMessageIntegrity, messageIntegrity))
		message.Body = attrs.Encode()
	}
	client.conn.WriteToUDP(message.Encode(), client.addr)

	n, err := client.conn.Read(client.readBuf)
	if err != nil {
		return err
	}
	res, err := ParseSTUNMessage(client.readBuf[:n])
	if err != nil {
		return err
	}
	if res.IsError() {
		return errors.New(STUNErrorMessage(*res).ErrorMessage())
	}

	return nil
}

func (client *Client) Send(peer net.IP, port int, body []byte) {
	addr := NewXorAddressAttribute(AttributeXorPeerAddress)
	addr.Family = AddressFamilyV4
	addr.Address = peer
	addr.Port = port

	attrs := Attributes([]Attribute{addr, NewBaseAttribute(AttributeDontFragment, nil), NewBaseAttribute(AttributeData, body)}).Encode()
	message := NewSTUNMessage(MethodSend)
	message.Body = attrs
	client.conn.WriteToUDP(message.Encode(), client.addr)
}

func (client *Client) StartReading() {
	for {
		n, err := client.conn.Read(client.readBuf)
		if err != nil {
			break
		}

		res, err := ParseSTUNMessage(client.readBuf[:n])
		if err != nil {
			client.readChan <- client.readBuf[:n]
			return
		}
		client.dispatchMessage(res)
	}
}

func (client *Client) Read() []byte {
	return <-client.readChan
}

// channelNumber in the range 16384 through 0x32766
func (client *Client) ChannelBind(channelNumber int) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(channelNumber))
	buf = append(buf, 0x00, 0x00)
	attrs := Attributes([]Attribute{NewBaseAttribute(AttributeChannelNumber, buf), NewBaseAttribute(AttributeXorPeerAddress, []byte{})}).Encode()
	message := NewSTUNMessage(MethodChannelBind)
	message.Body = attrs

	log.Printf("% x", message.Encode())
	client.conn.WriteToUDP(message.Encode(), client.addr)

	n, _ := client.conn.Read(client.readBuf)
	res, _ := ParseSTUNMessage(client.readBuf[:n])
	if res.IsError() {
		log.Print(STUNErrorMessage(*res).ErrorMessage())
		return
	}
	resAttrs, _ := ParseAttributes(res.Body)
	log.Print(len(resAttrs))
	log.Print(resAttrs)
}

func (client *Client) dispatchMessage(message *STUNMessage) {
	if message.IsError() {
		log.Print(STUNErrorMessage(*message).ErrorMessage())
	}
}

func (client *Client) allocateWithAuthenticate() (net.IP, int, error) {
	attrs := Attributes([]Attribute{
		NewBaseAttribute(AttributeRequestedTransport, TransportUDP),
		NewBaseAttribute(AttributeUsername, []byte(client.Username)),
		NewBaseAttribute(AttributeRealm, client.realm),
		NewBaseAttribute(AttributeNonce, client.nonce),
	})
	message := NewSTUNMessage(MethodAllocate)
	message.Body = attrs.Encode()

	messageIntegrity := message.Authenticate(client.realm, client.Username, client.Password)
	attrs = append(attrs, NewBaseAttribute(AttributeMessageIntegrity, messageIntegrity))
	message.Body = attrs.Encode()
	buf := message.Encode()

	client.conn.WriteToUDP(buf, client.addr)

	n, err := client.conn.Read(client.readBuf)
	if err != nil {
		return nil, -1, err
	}
	res, err := ParseSTUNMessage(client.readBuf[:n])
	if err != nil {
		return nil, -1, err
	}
	if res.IsError() {
		return nil, -1, errors.New(STUNErrorMessage(*res).ErrorMessage())
	}

	resAttrs, err := res.Attributes()
	if err != nil {
		return nil, -1, err
	}
	var mappedAddress XorAddressAttribute
	for _, attr := range resAttrs {
		if attr.Key().TypeString() == AttributeXorMappedAddress {
			mappedAddress = attr.(XorAddressAttribute)
			break
		}
	}
	client.authRequire = true

	err = client.RefreshAllocation()
	if err != nil {
		return nil, -1, err
	}
	return mappedAddress.Address, mappedAddress.Port, nil
}
