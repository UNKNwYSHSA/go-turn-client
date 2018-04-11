package turn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
)

var MessageCookie = []byte{0x21, 0x12, 0xA4, 0x42}
var (
	AllocateRequest  = []byte{0x00, 0x03} // RFC5766
	AllocateSuccess  = []byte{0x01, 0x03} // RFC5766
	CreatePermission = []byte{0x00, 0x08} // RFC5766
	ChannelBind      = []byte{0x00, 0x09} // RFC5766
)

var (
	TransportUDP = []byte{0x11, 0x00, 0x00, 0x00}
)

var (
	ErrInvalidPacket = errors.New("invalid packet")
)

type Client struct {
	conn net.Conn
}

type STUNMessage struct {
	Type          []byte
	TransactionId []byte
	Body          []byte
}

type STUNErrorMessage STUNMessage

func Dial(addr string) *Client {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil
	}

	return &Client{conn: conn}
}

func (client *Client) Allocate() {
	attrs := Attributes([]Attribute{{Key: AttributeRequestedTransport, Value: TransportUDP}}).Encode()
	message := NewSTUNMessage(AllocateRequest)
	message.Body = attrs
	buf := message.Encode()

	client.conn.Write(buf)

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	log.Printf("% x", readBuf[:n])
	res, _ := ParseSTUNMessage(readBuf[:n])
	resAttrs, _ := ParseAttributes(res.Body)
	log.Print(len(resAttrs))
	log.Print(resAttrs)
}

func (client *Client) CreatePermission() {

}

// channelNumber in the range 16384 through 0x32766
func (client *Client) ChannelBind(channelNumber int) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(channelNumber))
	buf = append(buf, 0x00, 0x00)
	attrs := Attributes([]Attribute{{Key: AttributeChannelNumber, Value: buf}, {Key: AttributeXorPeerAddress, Value: []byte{}}}).Encode()
	message := NewSTUNMessage(ChannelBind)
	message.Body = attrs

	log.Printf("% x", message.Encode())
	client.conn.Write(message.Encode())

	readBuf := make([]byte, 1500)
	n, _ := client.conn.Read(readBuf)
	res, _ := ParseSTUNMessage(readBuf[:n])
	if res.IsError() {
		log.Print(STUNErrorMessage(res).ErrorMessage())
		return
	}
	resAttrs, _ := ParseAttributes(res.Body)
	log.Print(len(resAttrs))
	log.Print(resAttrs)
}

func ParseSTUNMessage(buf []byte) (STUNMessage, error) {
	if buf[0] != 0x01 {
		return STUNMessage{}, ErrInvalidPacket
	}
	message := &STUNMessage{Type: buf[:2], TransactionId: buf[8:20]}
	length := binary.BigEndian.Uint16(buf[2:4])
	message.Body = buf[20 : 20+length]
	return *message, nil
}

func NewSTUNMessage(t []byte) STUNMessage {
	transactionId := make([]byte, 12)
	rand.Read(transactionId)

	return STUNMessage{Type: t, TransactionId: transactionId}
}

func (message STUNMessage) Encode() []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(message.Type)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(message.Body)))
	buf.Write(lenBuf)

	buf.Write(MessageCookie)
	buf.Write(message.TransactionId)

	buf.Write(message.Body)
	return buf.Bytes()
}

func (message STUNMessage) IsError() bool {
	return 0x10&message.Type[1] == 0x10
}

func (message STUNErrorMessage) ErrorMessage() string {
	attrs, _ := ParseAttributes(message.Body)
	var errorCodeAttr Attribute
	for _, attr := range attrs {
		if attr.Key[0] == AttributeErrorCode[0] && attr.Key[1] == AttributeErrorCode[1] {
			errorCodeAttr = attr
			break
		}
	}
	c := int(errorCodeAttr.Value[2])
	num := int(errorCodeAttr.Value[3])

	return fmt.Sprintf("Code: %d, Message: %s", c*100+int(num), string(errorCodeAttr.Value[4:]))
}
