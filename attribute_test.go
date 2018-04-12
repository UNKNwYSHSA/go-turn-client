package turn

import (
	"net"
	"reflect"
	"testing"
)

func TestXorAddressAttribute(t *testing.T) {
	attr := XorAddressAttribute{key: AttributeXorMappedAddress, Family: AddressFamilyV4, Port: 51781, Address: []byte{127, 0, 0, 1}}
	if !reflect.DeepEqual(attr.Key(), AttributeXorMappedAddress) {
		t.Fatal("RawKey is mismatch")
	}
	if !reflect.DeepEqual(attr.Value(), []byte{0x00, 0x01, 0xeb, 0x57, 0x5e, 0x12, 0xa4, 0x43}) {
		t.Fatalf("RawValue is mismatch: % x", attr.Value())
	}

	attr = ParseXorAddressAttribute(AttributeXorMappedAddress, []byte{0x00, 0x01, 0xeb, 0x57, 0x5e, 0x12, 0xa4, 0x43})
	if attr.Port != 51781 {
		t.Fatalf("Port is mismatch: %d", attr.Port)
	}
	if !reflect.DeepEqual(attr.Address, net.IP([]byte{127, 0, 0, 1})) {
		t.Fatalf("Address is mismatch: %v", attr.Address)
	}
}
