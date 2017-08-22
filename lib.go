package bertlv

import (
	"encoding/binary"
	"errors"
)

// Returns: <full length of tlv frame>, <tag number>, <value bytes>, <error>
func Decode(p []byte) (n int, t []byte, v []byte, err error) {
	if len(p) < 2 {
		err = errors.New("Data too short!")
		return
	}

	if p[0]&31 != 31 {
		t = []byte{p[0]}
	} else {
		t = make([]byte, 1, 8)
		t[0] = p[0]
		for i := 1; i < len(p); i++ {
			t = append(t, p[i])
			if p[i]&128 != 128 {
				break
			}
		}
	}
	offs := len(t)
	if offs == len(p) {
		t = nil
		err = errors.New("Invalid data!")
		return
	}

	var l uint64
	switch {
	case p[offs] < 0x80:
		l = uint64(p[offs])
		offs++
	case p[offs] > 0x80:
		ll := p[offs] - 0x80
		switch {
		case ll > 8:
			err = errors.New("Length overflow!")
			return
		case ll > 4:
			buf := make([]byte, 8)
			copy(buf, p[offs+8-int(p[offs]):offs+8])
			l = binary.BigEndian.Uint64(buf)
		case ll > 2:
			buf := make([]byte, 4)
			copy(buf, p[offs:])
			copy(buf, p[offs+4-int(p[offs]):offs+4])
			l = uint64(binary.BigEndian.Uint32(buf))
		case ll > 1:
			buf := make([]byte, 2)
			copy(buf, p[offs:])
			copy(buf, p[offs+2-int(p[offs]):offs+2])
			l = uint64(binary.BigEndian.Uint16(buf))
		default:
			l = uint64(p[offs])
		}
		offs += int(ll)
	case p[offs] == 0x80:
		err = errors.New("Nested TLVs not yet implemented!")
		return
	}
	n = offs + int(l)
	v = p[offs:n]
	return
}
