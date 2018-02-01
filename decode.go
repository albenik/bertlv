package bertlv

import (
	"bytes"
	"encoding/binary"
	errs "errors"

	"github.com/albenik/goerrors"
)

var errUndefinedLength = errs.New("undefined length")

func Decode(p []byte) (*TLV, error) {
	tag, err := decodeTag(p)
	if err != nil {
		return nil, err
	}

	if tag[0]&0x20 == 0x20 {
		list, undef, err := decodeComplex(p[len(tag):])
		if err != nil {
			return nil, errors.Wrap(err, "tlv parse error")
		}
		return &TLV{T: tag, LUndef: undef, Children: list}, nil
	}

	n, l, err := decodeLen(p[len(tag):])
	if err != nil {
		return nil, errors.Wrap(err, "simple tlv parse error")
	}

	tlSize := uint64(len(tag)) + uint64(n)
	if tlSize+l > uint64(len(p)) {
		return nil, errors.Newf("[% X] %d %d", p, tlSize, l)
		//return nil, errors.New("simple tlv value data too short")
	}

	if l > 0 {
		return &TLV{T: tag, V: p[tlSize : tlSize+l]}, nil
	} else {
		return &TLV{T: tag}, nil
	}
}

func decodeTag(b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, errors.New("TLV data size cannot be less than two bytes")
	}
	if b[0]&0x1F != 0x1F {
		return b[0:1], nil
	}
	for i := 1; i < len(b); i++ {
		if b[i]&0x80 != 0x80 {
			return b[:i+1], nil
		}
	}
	return nil, errors.New("invalid tag value")
}

// Decodes TLV Length data
// Returns: length data size, length value, error
func decodeLen(b []byte) (uint8, uint64, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("length value data cannot be empty")
	}

	if b[0] == 0x80 { // Undefined length for complex tlv
		return 1, 0, errUndefinedLength
	}

	if b[0] < 0x80 { // One-byte length
		return 1, uint64(b[0]), nil
	}

	vsize := b[0] - 0x80 // Multibyte length
	if vsize > 8 {       // uint64 overflow
		return 0, 0, errors.New("length data size overlow uint64")
	}

	if len(b) < int(vsize)+1 {
		return 0, 0, errors.New("invalid length value")
	}

	var tmp [8]byte
	copy(tmp[8-vsize:], b[1:vsize+1])
	return vsize + 1, binary.BigEndian.Uint64(tmp[:]), nil
}

func decodeComplex(p []byte) ([]*TLV, bool, error) {
	n, l, err := decodeLen(p[:])
	if err != nil && err != errUndefinedLength {
		return nil, false, errors.Wrap(err, "complex tlv parse error")
	}

	if int(n) > len(p)-1 {
		return nil, false, errors.New("complex tlv data too short")
	}

	list := make([]*TLV, 0, 2)
	data := p[n:]
	dlen := uint64(len(data))
	offs := uint64(0)

	if err == errUndefinedLength {
		for offs < dlen {
			if bytes.HasPrefix(data[offs:], []byte{0x00, 0x00}) {
				return list, true, nil
			}
			tlv, err := Decode(data[offs:])
			if err != nil {
				return nil, false, errors.Wrap(err, "complex tlv parse error")
			}
			list = append(list, tlv)
			offs += tlv.Size()
		}
		return nil, false, errors.New("comlex tlv with undefined length NULL tlv missing at end")
	} else {
		for offs < l {
			tlv, err := Decode(data[offs:])
			if err != nil {
				return nil, false, errors.Wrap(err, "complex tlv parse error")
			}
			list = append(list, tlv)
			offs += tlv.Size()
		}
		return list, false, nil
	}
}
