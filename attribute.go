package turn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

//var (
//	AttributeMappedAddress      = []byte{0x00, 0x01} // RFC3489
//	AttributeSourceAddress      = []byte{0x00, 0x04} // RFC3489
//	AttributeUsername           = []byte{0x00, 0x06} // RFC5389
//	AttributeMessageIntegrity   = []byte{0x00, 0x08} // RFC3489
//	AttributeErrorCode          = []byte{0x00, 0x09} // RFC5389
//	AttributeUnknown            = []byte{0x00, 0x0a} // RFC3489
//	AttributeChannelNumber      = []byte{0x00, 0x0c} // RFC5766
//	AttributeLifetime           = []byte{0x00, 0x0d} // RFC5766
//	AttributeXorPeerAddress     = []byte{0x00, 0x12} // RFC5766
//	AttributeData               = []byte{0x00, 0x13} // RFC5766
//	AttributeRealm              = []byte{0x00, 0x14} // RFC5766
//	AttributeNonce              = []byte{0x00, 0x15} // RFC5766
//	AttributeXorRelayedAddress  = []byte{0x00, 0x16} // RFC5766
//	AttributeRequestedTransport = []byte{0x00, 0x19} // RFC5766
//	AttributeDontFragment       = []byte{0x00, 0x1a} // RFC5766
//	AttributeXorMappedAddress   = []byte{0x00, 0x20} // RFC5389
//	AttributeReservationToken   = []byte{0x00, 0x22} // RFC5766
//	AttributeSoftware           = []byte{0x80, 0x22} // RFC5389
//)

const (
	AttributeMappedAddress      = "MAPPED-ADDRESS"
	AttributeSourceAddress      = "SOURCE-ADDRESS"
	AttributeUsername           = "USERNAME"
	AttributeMessageIntegrity   = "MESSAGE-INTEGRITY"
	AttributeErrorCode          = "ERROR-CODE"
	AttributeUnknown            = "UNKNOWN"
	AttributeChannelNumber      = "CHANNEL-NUMBER"
	AttributeLifetime           = "LIFETIME"
	AttributeXorPeerAddress     = "XOR-PEER-ADDRESS"
	AttributeData               = "DATA"
	AttributeRealm              = "REALM"
	AttributeNonce              = "NONCE"
	AttributeXorRelayedAddress  = "XOR-RELAYED-ADDRESS"
	AttributeRequestedTransport = "REQUESTED-TRANSPORT"
	AttributeDontFragment       = "DONT-FRAGMENT"
	AttributeXorMappedAddress   = "XOR-MAPPED-ADDRESS"
	AttributeReservationToken   = "RESERVATION-TOKEN"
	AttributeSoftware           = "SOFTWARE"
)

var AttributeRegistry = map[string][]byte{
	AttributeMappedAddress:      {0x00, 0x01},
	AttributeSourceAddress:      {0x00, 0x04}, // RFC3489
	AttributeUsername:           {0x00, 0x06}, // RFC5389
	AttributeMessageIntegrity:   {0x00, 0x08}, // RFC3489
	AttributeErrorCode:          {0x00, 0x09}, // RFC5389
	AttributeUnknown:            {0x00, 0x0a}, // RFC3489
	AttributeChannelNumber:      {0x00, 0x0c}, // RFC5766
	AttributeLifetime:           {0x00, 0x0d}, // RFC5766
	AttributeXorPeerAddress:     {0x00, 0x12}, // RFC5766
	AttributeData:               {0x00, 0x13}, // RFC5766
	AttributeRealm:              {0x00, 0x14}, // RFC5766
	AttributeNonce:              {0x00, 0x15}, // RFC5766
	AttributeXorRelayedAddress:  {0x00, 0x16}, // RFC5766
	AttributeRequestedTransport: {0x00, 0x19}, // RFC5766
	AttributeDontFragment:       {0x00, 0x1a}, // RFC5766
	AttributeXorMappedAddress:   {0x00, 0x20}, // RFC5389
	AttributeReservationToken:   {0x00, 0x22}, // RFC5766
	AttributeSoftware:           {0x80, 0x22}, // RFC5389
}
var TreeAttribute TwoBytesTree

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

func init() {
	TreeAttribute = make(map[byte]map[byte]string)

	for k, v := range AttributeRegistry {
		if _, ok := TreeAttribute[v[0]]; ok == false {
			TreeAttribute[v[0]] = make(map[byte]string)
		}
		TreeAttribute[v[0]][v[1]] = k
	}
}

func ParseAttributes(buf []byte) (Attributes, error) {
	attrs := make([]Attribute, 0)
	for {
		if len(buf) < 4 {
			break
		}

		length := int(binary.BigEndian.Uint16(buf[2:4]))
		padding := 0
		if length%4 != 0 {
			padding = 4 - length%4
		}
		switch AttributeKey(buf[:2]).TypeString() {
		case AttributeXorRelayedAddress, AttributeXorMappedAddress, AttributeXorPeerAddress:
			attr := ParseXorAddressAttribute(buf[:2], buf[4:4+length])
			attrs = append(attrs, attr)
		default:
			attr := new(BaseAttribute)
			attr.RawKey = buf[:2]
			attr.RawValue = buf[4 : 4+length]
			attrs = append(attrs, *attr)
		}
		buf = buf[4+length+padding:]
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

func NewBaseAttribute(key string, value []byte) *BaseAttribute {
	return &BaseAttribute{RawKey: AttributeRegistry[key], RawValue: value}
}

func (attr BaseAttribute) Key() AttributeKey {
	return attr.RawKey
}

func (attr BaseAttribute) Value() []byte {
	if len(attr.RawValue)%4 != 0 {
		padding := 4 - len(attr.RawValue)%4
		p := make([]byte, padding)
		return append(attr.RawValue, p...)
	} else {
		return attr.RawValue
	}
}

func (attr BaseAttribute) String() string {
	return fmt.Sprintf("RawKey: %s RawValue: % x", attr.RawKey, string(attr.RawValue))
}

func NewXorAddressAttribute(key string) *XorAddressAttribute {
	return &XorAddressAttribute{key: AttributeRegistry[key]}
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
	return TreeAttribute[k[0]][k[1]]

	return fmt.Sprintf("% x", []byte(k))
}
