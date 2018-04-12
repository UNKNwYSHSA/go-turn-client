package turn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

var MessageCookie = []byte{0x21, 0x12, 0xA4, 0x42}
var (
	MethodAllocate          = []byte{0x00, 0x03} // RFC5766
	MethodRefreshAllocation = []byte{0x00, 0x04} // RFC5766
	MethodSend              = []byte{0x00, 0x16} // RFC5766
	MethodData              = []byte{0x00, 0x07} // RFC5766
	MethodCreatePermission  = []byte{0x00, 0x08} // RFC5766
	MethodChannelBind       = []byte{0x00, 0x09} // RFC5766
)

type STUNMethod []byte

type STUNMessage struct {
	Type          STUNMethod
	TransactionId []byte
	Body          []byte

	attributes Attributes
}

type STUNErrorMessage STUNMessage

func ParseSTUNMessage(buf []byte) (*STUNMessage, error) {
	if buf[0] != 0x01 {
		return nil, ErrInvalidPacket
	}
	message := &STUNMessage{Type: buf[:2], TransactionId: buf[8:20]}
	length := binary.BigEndian.Uint16(buf[2:4])
	message.Body = buf[20 : 20+length]
	return message, nil
}

func NewSTUNMessage(t []byte) STUNMessage {
	transactionId := make([]byte, 12)
	rand.Read(transactionId)

	return STUNMessage{Type: t, TransactionId: transactionId}
}

func (message *STUNMessage) Attributes() (Attributes, error) {
	if message.attributes == nil {
		attrs, err := ParseAttributes(message.Body)
		if err != nil {
			return attrs, err
		}
		message.attributes = attrs
	}

	return message.attributes, nil
}

func (message *STUNMessage) Encode() []byte {
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

func (message *STUNMessage) IsError() bool {
	return 0x10&message.Type[1] == 0x10
}

func (message *STUNMessage) String() string {
	return fmt.Sprintf("Method: %s", message.Type)
}

func (message STUNErrorMessage) ErrorMessage() string {
	attrs, _ := ParseAttributes(message.Body)
	var errorCodeAttr Attribute
	for _, attr := range attrs {
		if attr.Key()[0] == AttributeErrorCode[0] && attr.Key()[1] == AttributeErrorCode[1] {
			errorCodeAttr = attr
			break
		}
	}
	c := int(errorCodeAttr.Value()[2])
	num := int(errorCodeAttr.Value()[3])

	return fmt.Sprintf("Code: %d, Message: %s", c*100+int(num), string(errorCodeAttr.Value()[4:]))
}

func (m STUNMethod) String() string {
	if m[1] == MethodAllocate[1] {
		return "Allocate"
	}
	if m[1] == MethodRefreshAllocation[1] {
		return "Refresh"
	}
	if m[1] == MethodChannelBind[1] {
		return "ChannelBind"
	}
	if m[1] == MethodCreatePermission[1] {
		return "CreatePermission"
	}
	if m[1] == MethodData[1] {
		return "Data"
	}
	if m[1] == MethodSend[1] {
		return "Send"
	}

	return fmt.Sprintf("% x", []byte(m))
}
