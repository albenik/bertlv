package bertlv

import (
	"bytes"
	"encoding/binary"
	"math/bits"

	"github.com/albenik/goerrors"
)

func calcLenSize(l uint64) uint8 {
	if l < 0x81 {
		return 1
	}
	n := bits.Len64(l)
	if n%8 != 0 {
		n = (n / 8) + 1
	} else {
		n = n / 8
	}
	return uint8(n + 1)
}

func encodeLen(l uint64) []byte {
	if l < 0x80 {
		return []byte{byte(l)}
	}

	n := calcLenSize(l) - 1
	b := make([]byte, 9)
	binary.BigEndian.PutUint64(b[1:], l)

	b[8-n] = n + 0x80
	return b[8-n:]
}

func encodeComlex(buf *bytes.Buffer, tlv *TLV) error {
	if len(tlv.Children) == 0 {
		return errors.Newf("missing children for complex tag [% X]", tlv.T)
	}

	if tlv.LUndef {
		buf.WriteByte(0x80)
	} else {
		buf.Write(encodeLen(tlv.L()))
	}

	for _, tlv2 := range tlv.Children {
		if err := encode(buf, tlv2); err != nil {
			return err
		}
	}

	if tlv.LUndef {
		buf.Write([]byte{0x00, 0x00})
	}

	return nil
}

func encode(buf *bytes.Buffer, tlv *TLV) error {
	buf.Write(tlv.T)
	if tlv.IsComplex() {
		return encodeComlex(buf, tlv)
	}

	if tlv.LUndef {
		return errors.New("length cannot be undefined for simle tag")
	}

	buf.Write(encodeLen(tlv.L()))
	buf.Write(tlv.V)

	return nil
}

func Encode(tlv *TLV) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, tlv.Size()))
	if err := encode(buf, tlv); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
