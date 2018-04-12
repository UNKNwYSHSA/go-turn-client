package turn

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
)

var (
	TransportUDP = []byte{0x11, 0x00, 0x00, 0x00}
)

var (
	ErrInvalidPacket = errors.New("invalid packet")
)

type Client struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func Dial(addr string) *Client {
	a, _ := net.ResolveUDPAddr("udp", ":")
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil
	}
	turnAddr, _ := net.ResolveUDPAddr("udp", addr)

	return &Client{conn: conn, addr: turnAddr}
}

func (client *Client) Allocate() (net.IP, int) {
	attrs := Attributes([]Attribute{BaseAttribute{RawKey: AttributeRequestedTransport, RawValue: TransportUDP}}).Encode()
	message := NewSTUNMessage(MethodAllocate)
	message.Body = attrs
	buf := message.Encode()

	client.conn.WriteToUDP(buf, client.addr)

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	res, _ := ParseSTUNMessage(readBuf[:n])
	log.Print(res)
	log.Print(res.Attributes())

	resAttrs, _ := res.Attributes()
	var mappedAddress XorAddressAttribute
	for _, attr := range resAttrs {
		if attr.Key().TypeString() == "XOR-MAPPED-ADDRESS" {
			mappedAddress = attr.(XorAddressAttribute)
			break
		}
	}
	return mappedAddress.Address, mappedAddress.Port
}

func (client *Client) RefreshAllocation() {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(600))
	attrs := Attributes([]Attribute{BaseAttribute{RawKey: AttributeLifetime, RawValue: buf}}).Encode()
	message := NewSTUNMessage(MethodRefreshAllocation)
	message.Body = attrs
	client.conn.WriteToUDP(message.Encode(), client.addr)

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	log.Printf("% x", readBuf[:n])
	res, _ := ParseSTUNMessage(readBuf[:n])
	resAttrs, _ := ParseAttributes(res.Body)
	log.Print(len(resAttrs))
	log.Print(resAttrs)
}

func (client *Client) CreatePermission(peer net.IP) {
	addr := NewXorAddressAttribute(AttributeXorPeerAddress)
	addr.Family = AddressFamilyV4
	addr.Address = peer

	attrs := Attributes([]Attribute{addr}).Encode()
	message := NewSTUNMessage(MethodCreatePermission)
	message.Body = attrs
	client.conn.WriteToUDP(message.Encode(), client.addr)

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	log.Printf("% x", readBuf[:n])
	res, _ := ParseSTUNMessage(readBuf[:n])
	if res.IsError() {
		log.Print(STUNErrorMessage(*res).ErrorMessage())
	} else {
		log.Print(res.Attributes())
	}
}

func (client *Client) Send(peer net.IP, port int, body []byte) {
	addr := NewXorAddressAttribute(AttributeXorPeerAddress)
	addr.Family = AddressFamilyV4
	addr.Address = peer
	addr.Port = port

	attrs := Attributes([]Attribute{addr, BaseAttribute{RawKey: AttributeDontFragment}, BaseAttribute{RawKey: AttributeData, RawValue: body}}).Encode()
	message := NewSTUNMessage(MethodSend)
	message.Body = attrs
	client.conn.WriteToUDP(message.Encode(), client.addr)
}

func (client *Client) Data() []byte {
	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	log.Printf("% x", readBuf[:n])

	return readBuf[:n]
}

// channelNumber in the range 16384 through 0x32766
func (client *Client) ChannelBind(channelNumber int) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(channelNumber))
	buf = append(buf, 0x00, 0x00)
	attrs := Attributes([]Attribute{BaseAttribute{RawKey: AttributeChannelNumber, RawValue: buf}, BaseAttribute{RawKey: AttributeXorPeerAddress, RawValue: []byte{}}}).Encode()
	message := NewSTUNMessage(MethodChannelBind)
	message.Body = attrs

	log.Printf("% x", message.Encode())
	client.conn.WriteToUDP(message.Encode(), client.addr)

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	res, _ := ParseSTUNMessage(readBuf[:n])
	if res.IsError() {
		log.Print(STUNErrorMessage(*res).ErrorMessage())
		return
	}
	resAttrs, _ := ParseAttributes(res.Body)
	log.Print(len(resAttrs))
	log.Print(resAttrs)
}
