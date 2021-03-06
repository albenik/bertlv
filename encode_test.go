package bertlv_test

import (
	"testing"

	"github.com/albenik/bertlv"
	"github.com/stretchr/testify/assert"
)

var testdata = []struct {
	tlv  *bertlv.TLV
	data []byte
}{
	{ // 1
		tlv: &bertlv.TLV{
			T: []byte{0x4f},
			V: []byte{0x11},
		},
		data: []byte{0x4F, 0x01, 0x11},
	},
	{ // 2
		tlv: &bertlv.TLV{
			T: []byte{0x5F, 0x20},
			V: make([]byte, 0xFF),
		},
		data: append([]byte{0x5F, 0x20, 0x81, 0xFF}, make([]byte, 0xFF)...),
	},
	{ // 3
		tlv: &bertlv.TLV{
			T: []byte{0xE2},
			Children: []*bertlv.TLV{
				{T: []byte{0x4F}, V: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}},
				{T: []byte{0x1F, 0x03}, V: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C}},
			},
		},
		data: []byte{
			0xE2 /**/, 0x17,
			0x4F /**/, 0x06 /**/, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			0x1F, 0x03 /**/, 0x0C /**/, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
		},
	},
	{ // 4
		tlv: &bertlv.TLV{
			T:      []byte{0xE2},
			LUndef: true,
			Children: []*bertlv.TLV{
				{T: []byte{0x4F}, V: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}},
				{T: []byte{0x1F, 0x03}, V: []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C}},
			},
		},
		data: []byte{
			0xE2 /**/, 0x80,
			0x4F /**/, 0x06 /**/, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			0x1F, 0x03 /**/, 0x0C /**/, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
			0x00, 0x00,
		},
	},
}

func TestEncode(t *testing.T) {
	for n, test := range testdata {
		const msg = "Record %d"
		data, err := bertlv.Encode(test.tlv)
		if !assert.NoError(t, err, msg, n+1) {
			t.FailNow()
		}
		if assert.Equal(t, uint64(len(test.data)), test.tlv.Size(), msg, n+1) {
			assert.Equal(t, test.data, data, msg, n+1)
		}
	}
}
