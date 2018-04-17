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
	Attrs         Attributes

	body  []byte
	error bool
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
	e := 0x01&buf[0] == 0x01 && 0x10&buf[1] == 0x10
	buf[0] &^= 0x01
	buf[1] &^= 0x10
	t, err := TreeMethod.Find(buf[:2])
	if err != nil {
		return nil, err
	}

	tBuf := make([]byte, 12)
	copy(tBuf, buf[8:20])
	message := &STUNMessage{Type: t, TransactionId: tBuf, error: e}
	length := binary.BigEndian.Uint16(buf[2:4])
	b := make([]byte, length)
	copy(b, buf[20:20+length])
	message.body = b

	return message, nil
}

func NewSTUNMessage(t string) *STUNMessage {
	transactionId := make([]byte, 12)
	rand.Read(transactionId)

	return &STUNMessage{Type: t, TransactionId: transactionId}
}

func (message *STUNMessage) Attributes() (Attributes, error) {
	if message.Attrs == nil {
		attrs, err := ParseAttributes(message.body)
		if err != nil {
			return attrs, err
		}
		message.Attrs = attrs
	}

	return message.Attrs, nil
}

func (message *STUNMessage) Encode() []byte {
	message.body = message.Attrs.Encode()
	return message.EncodeWithLength(len(message.body))
}

func (message *STUNMessage) EncodeWithLength(length int) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.Write(MethodRegistry[message.Type])
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(length))
	buf.Write(lenBuf)

	buf.Write(MessageCookie)
	buf.Write(message.TransactionId)

	if message.body != nil {
		buf.Write(message.body)
	} else {
		buf.Write(message.Attrs.Encode())
	}
	return buf.Bytes()
}

func (message *STUNMessage) MessageIntegrity(realm, username, password []byte) []byte {
	seed := bytes.Join([][]byte{username, realm, password}, []byte(":"))

	h := md5.Sum(seed)
	mac := hmac.New(sha1.New, h[:])
	message.body = message.Attrs.Encode()
	mac.Write(message.EncodeWithLength(len(message.body) + 24))
	return mac.Sum(nil)
}

func (message *STUNMessage) IsError() bool {
	return message.error
}

func (message *STUNMessage) String() string {
	return fmt.Sprintf("Method: %s", message.Type)
}

func (message STUNErrorMessage) ErrorMessage() string {
	attr := message.findErrorCode()
	c := int(attr.Value()[2])
	num := int(attr.Value()[3])

	return fmt.Sprintf("Code: %d, Message: %s", c*100+int(num), string(attr.Value()[4:]))
}

func (message STUNErrorMessage) Code() int {
	attr := message.findErrorCode()
	c := int(attr.Value()[2])
	num := int(attr.Value()[3])

	return c*100 + int(num)
}

func (message STUNErrorMessage) findErrorCode() Attribute {
	attrs, _ := ParseAttributes(message.body)
	var errorCodeAttr Attribute
	for _, attr := range attrs {
		if attr.Key().TypeString() == AttributeErrorCode {
			errorCodeAttr = attr
			break
		}
	}
	return errorCodeAttr
}
