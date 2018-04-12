package turn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

var (
	AttributeMappedAddress      = []byte{0x00, 0x01} // RFC3489
	AttributeSourceAddress      = []byte{0x00, 0x04} // RFC3489
	AttributeUsername           = []byte{0x00, 0x06} // RFC5389
	AttributeErrorCode          = []byte{0x00, 0x09} // RFC5389
	AttributeUnknown            = []byte{0x00, 0x0a} // RFC3489
	AttributeChannelNumber      = []byte{0x00, 0x0c} // RFC5766
	AttributeLifetime           = []byte{0x00, 0x0d} // RFC5766
	AttributeXorPeerAddress     = []byte{0x00, 0x12} // RFC5766
	AttributeData               = []byte{0x00, 0x13} // RFC5766
	AttributeXorRelayedAddress  = []byte{0x00, 0x16} // RFC5766
	AttributeRequestedTransport = []byte{0x00, 0x19} // RFC5766
	AttributeDontFragment       = []byte{0x00, 0x1a} // RFC5766
	AttributeXorMappedAddress   = []byte{0x00, 0x20} // RFC5389
	AttributeReservationToken   = []byte{0x00, 0x22} // RFC5766
	AttributeSoftware           = []byte{0x80, 0x22} // RFC5389
)

const (
	AddressFamilyV4 = 1 + iota
	AddressFamilyV6
)

type AddressFamily int

type AttributeKey []byte

type BaseAttribute struct {
	RawKey   AttributeKey
	RawValue []byte
}

type XorAddressAttribute struct {
	key     AttributeKey
	Family  AddressFamily
	Port    int
	Address net.IP
}

type Attribute interface {
	Key() AttributeKey
	Value() []byte
}

type Attributes []Attribute

func ParseAttributes(buf []byte) (Attributes, error) {
	attrs := make([]Attribute, 0)
	for {
		if len(buf) < 4 {
			break
		}

		length := binary.BigEndian.Uint16(buf[2:4])
		switch AttributeKey(buf[:2]).TypeString() {
		case "XOR-RELAYED-ADDRESS", "XOR-MAPPED-ADDRESS":
			attr := ParseXorAddressAttribute(buf[:2], buf[4:4+length])
			attrs = append(attrs, attr)
		default:
			attr := new(BaseAttribute)
			attr.RawKey = buf[:2]
			attr.RawValue = buf[4 : 4+length]
			attrs = append(attrs, *attr)
		}
		buf = buf[4+length:]
	}

	return Attributes(attrs), nil
}

func (attrs Attributes) Encode() []byte {
	buf := bytes.NewBuffer([]byte{})
	length := make([]byte, 2)
	for _, a := range attrs {
		buf.Write(a.Key())
		binary.BigEndian.PutUint16(length, uint16(len(a.Value())))
		buf.Write(length)
		if len(a.Value()) > 0 {
			buf.Write(a.Value())
		}
	}

	return buf.Bytes()
}

func (attr BaseAttribute) Key() AttributeKey {
	return attr.RawKey
}

func (attr BaseAttribute) Value() []byte {
	return attr.RawValue
}

func (attr BaseAttribute) String() string {
	return fmt.Sprintf("RawKey: %s RawValue: % x", attr.RawKey, string(attr.RawValue))
}

func NewXorAddressAttribute(key []byte) *XorAddressAttribute {
	return &XorAddressAttribute{key: key}
}

func ParseXorAddressAttribute(key, value []byte) XorAddressAttribute {
	value[2], value[3] = value[2]^MessageCookie[0], value[3]^MessageCookie[1]
	p := binary.BigEndian.Uint16(value[2:4])
	a := value[4:]
	for i := 0; i < len(a); i++ {
		a[i] = a[i] ^ MessageCookie[i%4]
	}

	return XorAddressAttribute{key: key, Port: int(p), Family: AddressFamilyV4, Address: net.IP(a)}
}

func (attr XorAddressAttribute) Key() AttributeKey {
	return attr.key
}

func (attr XorAddressAttribute) Value() []byte {
	buf := make([]byte, 4+len(attr.Address))
	if len(attr.Address) == 4 {
		buf[1] = AddressFamilyV4
	} else {
		buf[1] = AddressFamilyV6
	}
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(attr.Port))
	buf[2], buf[3] = b[0]^MessageCookie[0], b[1]^MessageCookie[1]
	for i := 0; i < len(attr.Address); i++ {
		buf[4+i] = attr.Address[i] ^ MessageCookie[i%4]
	}

	return buf
}

func (attr XorAddressAttribute) String() string {
	return fmt.Sprintf("Key: %s Address: %s Port: %d", attr.key.TypeString(), attr.Address, attr.Port)
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
	if k[0] == AttributeXorPeerAddress[0] && k[1] == AttributeXorPeerAddress[1] {
		return "XOR-PEER-ADDRESS"
	}
	if k[0] == AttributeMappedAddress[0] && k[1] == AttributeMappedAddress[1] {
		return "MAPPED-ADDRESS"
	}
	if k[0] == AttributeUnknown[0] && k[1] == AttributeUnknown[1] {
		return "UNKNOWN-ATTRIBUTES"
	}
	if k[0] == AttributeSourceAddress[0] && k[1] == AttributeSourceAddress[1] {
		return "SOURCE-ADDRESS"
	}
	if k[0] == AttributeDontFragment[0] && k[1] == AttributeDontFragment[1] {
		return "DONT-FRAGMENT"
	}

	return fmt.Sprintf("% x", []byte(k))
}
