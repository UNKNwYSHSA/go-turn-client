package turn

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

var MessageCookie = []byte{0x21, 0x12, 0xA4, 0x42}

const (
	MethodAllocate          = "Allocate"
	MethodRefreshAllocation = "Refresh"
	MethodSend              = "Send"
	MethodData              = "Data"
	MethodCreatePermission  = "CreatePermission"
	MethodChannelBind       = "CHannelBind"
)

var MethodRegistry = map[string][]byte{
	MethodAllocate:          {0x00, 0x03}, // RFC5766
	MethodRefreshAllocation: {0x00, 0x04}, // RFC5766
	MethodSend:              {0x00, 0x16}, // RFC5766
	MethodData:              {0x00, 0x07}, // RFC5766
	MethodCreatePermission:  {0x00, 0x08}, // RFC5766
	MethodChannelBind:       {0x00, 0x09}, // RFC5766
}
var TreeMethod TwoBytesTree

const (
	ErrorUnauthorized = 401
)

type STUNMessage struct {
	Type          string
	TransactionId []byte
	Body          []byte

	error      bool
	attributes Attributes
}

type STUNErrorMessage STUNMessage

func init() {
	TreeMethod = make(map[byte]map[byte]string)

	for k, v := range MethodRegistry {
		if _, ok := TreeMethod[v[0]]; ok == false {
			TreeMethod[v[0]] = make(map[byte]string)
		}
		TreeMethod[v[0]][v[1]] = k
	}
}

func ParseSTUNMessage(buf []byte) (*STUNMessage, error) {
	if buf[0] != 0x01 {
		return nil, ErrInvalidPacket
	}
	error := 0x10&buf[1] == 0x10
	buf[0] ^= 0x01
	buf[1] ^= 0x10
	t, err := TreeMethod.Find(buf[:2])
	if err != nil {
		return nil, err
	}

	tBuf := make([]byte, 12)
	copy(tBuf, buf[8:20])
	message := &STUNMessage{Type: t, TransactionId: tBuf, error: error}
	length := binary.BigEndian.Uint16(buf[2:4])
	b := make([]byte, length)
	copy(b, buf[20:20+length])
	message.Body = b

	return message, nil
}

func NewSTUNMessage(t string) STUNMessage {
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
	return message.EncodeWithLength(len(message.Body))
}

func (message *STUNMessage) EncodeWithLength(length int) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(MethodRegistry[message.Type])
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(length))
	buf.Write(lenBuf)

	buf.Write(MessageCookie)
	buf.Write(message.TransactionId)

	buf.Write(message.Body)
	return buf.Bytes()
}

func (message *STUNMessage) Authenticate(realm, username, password []byte) []byte {
	seed := bytes.Join([][]byte{username, realm, password}, []byte(":"))

	h := md5.Sum(seed)
	mac := hmac.New(sha1.New, h[:])
	mac.Write(message.EncodeWithLength(len(message.Body) + 24))
	return mac.Sum(nil)
}

func (message *STUNMessage) IsError() bool {
	return message.error
}

func (message *STUNMessage) String() string {
	return fmt.Sprintf("Method: %s", message.Type)
}

func (message STUNErrorMessage) ErrorMessage() string {
	attrs, _ := ParseAttributes(message.Body)
	var errorCodeAttr Attribute
	for _, attr := range attrs {
		a, err := TreeAttribute.Find(attr.Key())
		if err != nil {
			continue
		}
		if a == AttributeErrorCode {
			errorCodeAttr = attr
			break
		}
	}
	c := int(errorCodeAttr.Value()[2])
	num := int(errorCodeAttr.Value()[3])

	return fmt.Sprintf("Code: %d, Message: %s", c*100+int(num), string(errorCodeAttr.Value()[4:]))
}

func (message STUNErrorMessage) Code() int {
	attrs, _ := ParseAttributes(message.Body)
	var errorCodeAttr Attribute
	for _, attr := range attrs {
		a, err := TreeAttribute.Find(attr.Key())
		if err != nil {
			continue
		}
		if a == AttributeErrorCode {
			errorCodeAttr = attr
			break
		}
	}
	c := int(errorCodeAttr.Value()[2])
	num := int(errorCodeAttr.Value()[3])
	return c*100 + int(num)
}
