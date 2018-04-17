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
	message := NewSTUNMessage(MethodAllocate)
	message.Attrs = Attributes([]Attribute{NewBaseAttribute(AttributeRequestedTransport, TransportUDP)})
	client.sendRequest(message)

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
	if res.IsError() && STUNErrorMessage(*res).Code() == ErrorUnauthorized && !client.authRequire {
		client.authRequire = true
		for _, attr := range resAttrs {
			switch attr.Key().TypeString() {
			case AttributeNonce:
				client.nonce = attr.(BaseAttribute).RawValue
			case AttributeRealm:
				client.realm = attr.(BaseAttribute).RawValue
			}
		}

		return client.Allocate()
	}
	if res.IsError() {
		return nil, -1, errors.New(STUNErrorMessage(*res).ErrorMessage())
	}

	var relayedAddress XorAddressAttribute
	for _, attr := range resAttrs {
		if attr.Key().TypeString() == AttributeXorRelayedAddress {
			relayedAddress = attr.(XorAddressAttribute)
			break
		}
	}

	err = client.RefreshAllocation()
	if err != nil {
		return nil, -1, err
	}
	return relayedAddress.Address, relayedAddress.Port, nil
}

func (client *Client) RefreshAllocation() error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(600))
	message := NewSTUNMessage(MethodRefreshAllocation)
	message.Attrs = Attributes([]Attribute{NewBaseAttribute(AttributeLifetime, buf)})
	client.sendRequest(message)

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
	if len(peer) == 4 {
		addr.Family = AddressFamilyV4
	} else {
		addr.Family = AddressFamilyV6
	}
	addr.Address = peer

	message := NewSTUNMessage(MethodCreatePermission)
	message.Attrs = Attributes([]Attribute{addr})
	client.sendRequest(message)

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
	if len(peer) == 4 {
		addr.Family = AddressFamilyV4
	} else {
		addr.Family = AddressFamilyV6
	}
	addr.Address = peer
	addr.Port = port

	message := NewSTUNMessage(MethodSend)
	message.Attrs = Attributes([]Attribute{addr, NewBaseAttribute(AttributeDontFragment, nil), NewBaseAttribute(AttributeData, body)})
	client.conn.WriteToUDP(message.Encode(), client.addr)
}

func (client *Client) Read() ([]byte, error) {
	n, err := client.conn.Read(client.readBuf)
	if err != nil {
		return nil, err
	}

	for {
		res, err := ParseSTUNMessage(client.readBuf[:n])
		if err != nil {
			return client.readBuf[:n], nil
		}
		data := client.dispatchMessage(res)
		if len(data) > 0 {
			return data, nil
		}
	}
}

// channelNumber in the range 16384 through 32766
func (client *Client) ChannelBind(channelNumber int, peerIp net.IP, peerPort int) error {
	addr := NewXorAddressAttribute(AttributeXorPeerAddress)
	addr.Address = peerIp
	addr.Port = peerPort
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], uint16(channelNumber))

	message := NewSTUNMessage(MethodChannelBind)
	message.Attrs = Attributes([]Attribute{addr, NewBaseAttribute(AttributeChannelNumber, buf)})
	client.sendRequest(message)

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

func (client *Client) Shutdown() error {
	return client.conn.Close()
}

func (client *Client) sendRequest(message *STUNMessage) (int, error) {
	if client.authRequire {
		message.Attrs = append(message.Attrs,
			NewBaseAttribute(AttributeUsername, []byte(client.Username)),
			NewBaseAttribute(AttributeRealm, client.realm),
			NewBaseAttribute(AttributeNonce, client.nonce))
		messageIntegrity := message.MessageIntegrity(client.realm, client.Username, client.Password)
		message.Attrs = append(message.Attrs, NewBaseAttribute(AttributeMessageIntegrity, messageIntegrity))
	}

	return client.conn.WriteToUDP(message.Encode(), client.addr)
}

func (client *Client) dispatchMessage(message *STUNMessage) []byte {
	if message.IsError() {
		log.Print(STUNErrorMessage(*message).ErrorMessage())
	}

	switch message.Type {
	case MethodData:
		attrs, err := message.Attributes()
		if err != nil {
			return nil
		}
		for _, attr := range attrs {
			if attr.Key().TypeString() == AttributeData {
				return attr.Value()
			}
		}
	}

	return nil
}
