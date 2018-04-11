package turn

import "testing"

func TestAttributes_Encode(t *testing.T) {
	attrs := Attributes([]Attribute{{Key: AttributeRequestedTransport, Value: []byte{0x11, 0x00, 0x00, 0x00}}})
	b := attrs.Encode()
	if b[1] != 0x19 {
		t.Error("Type is mismatch")
	}
	if b[3] != 0x04 {
		t.Error("Length is mismatch")
	}
}
