package turn

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var (
	AttributeMappedAddress      = []byte{0x00, 0x01} // RFC3489
	AttributeUsername           = []byte{0x00, 0x06} // RFC5389
	AttributeErrorCode          = []byte{0x00, 0x09} // RFC5389
	AttributeChannelNumber      = []byte{0x00, 0x0c} // RFC5766
	AttributeLifetime           = []byte{0x00, 0x0d} // RFC5766
	AttributeXorPeerAddress     = []byte{0x00, 0x12} // RFC5766
	AttributeXorRelayedAddress  = []byte{0x00, 0x16} // RFC5766
	AttributeRequestedTransport = []byte{0x00, 0x19} // RFC5766
	AttributeXorMappedAddress   = []byte{0x00, 0x20} // RFC5389
	AttributeReservationToken   = []byte{0x00, 0x22} // RFC5766
	AttributeSoftware           = []byte{0x80, 0x22} // RFC5389
)

type AttributeKey []byte

type Attribute struct {
	Key   AttributeKey
	Value []byte
}

type Attributes []Attribute

func ParseAttributes(buf []byte) (Attributes, error) {
	attrs := make([]Attribute, 0)
	for {
		if len(buf) < 4 {
			break
		}

		attr := new(Attribute)
		attr.Key = buf[:2]
		length := binary.BigEndian.Uint16(buf[2:4])
		attr.Value = buf[4 : 4+length]
		buf = buf[4+length:]
		attrs = append(attrs, *attr)
	}

	return Attributes(attrs), nil
}

func (attrs Attributes) Encode() []byte {
	buf := bytes.NewBuffer([]byte{})
	length := make([]byte, 2)
	for _, a := range attrs {
		buf.Write(a.Key)
		binary.BigEndian.PutUint16(length, uint16(len(a.Value)))
		buf.Write(length)
		buf.Write(a.Value)
	}

	return buf.Bytes()
}

func (attr Attribute) String() string {
	return fmt.Sprintf("Key: %s Length: %d Value: % x", attr.Key, len(attr.Value), string(attr.Value))
}

func (k AttributeKey) String() string {
	return k.TypeString()
}

func (k AttributeKey) TypeString() string {
	if k[0] == AttributeXorRelayedAddress[0] && k[1] == AttributeXorRelayedAddress[1] {
		return "XOR-RELAYED-ADDRESS"
	}
	if k[0] == AttributeXorMappedAddress[0] && k[1] == AttributeXorMappedAddress[1] {
		return "XOR-MAPPED-ADDRESS"
	}
	if k[0] == AttributeLifetime[0] && k[1] == AttributeLifetime[1] {
		return "LIFETIME"
	}
	if k[0] == AttributeReservationToken[0] && k[1] == AttributeReservationToken[1] {
		return "RESERVATION-TOKEN"
	}
	if k[0] == AttributeSoftware[0] && k[1] == AttributeSoftware[1] {
		return "SOFTWARE"
	}
	if k[0] == AttributeUsername[0] && k[1] == AttributeUsername[1] {
		return "USERNAME"
	}
	if k[0] == AttributeChannelNumber[0] && k[1] == AttributeChannelNumber[1] {
		return "CHANNEL-NUMBER"
	}
	if k[0] == AttributeErrorCode[0] && k[1] == AttributeErrorCode[1] {
		return "ERROR-CODE"
	}
	if k[1] == AttributeXorPeerAddress[0] && k[1] == AttributeXorPeerAddress[1] {
		return "XOR-PEER-ADDRESS"
	}

	return fmt.Sprintf("% x", []byte(k))
}
