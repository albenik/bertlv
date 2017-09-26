package bertlv

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

/*
	Some tags explained from https://www.eftlab.co.uk/index.php/site-map/knowledge-base/145-emv-nfc-tags

	0x4f:['Application Identifier (AID)',BINARY,ITEM],
	0x50:['Application Label',TEXT,ITEM],
	0x57:['Track 2 Equivalent Data',BINARY,ITEM],
	0x5a:['Application Primary Account Number (PAN)',NUMERIC,ITEM],
	0x5f20:['Cardholder Name',TEXT,ITEM],
	0x5f24:['Application Expiration Date YYMMDD',NUMERIC,ITEM],
	0x5f25:['Application Effective Date YYMMDD',NUMERIC,ITEM],
	0x5f28:['Issuer Country Code',NUMERIC,ITEM],
	0x5f2a:['Transaction Currency Code',BINARY,VALUE],
	0x5f2d:['Language Preference',TEXT,ITEM],
	0x5f30:['Service Code',NUMERIC,ITEM],
	0x5f34:['Application Primary Account Number (PAN) Sequence Number',NUMERIC,ITEM],
	0x5f50:['Issuer URL',TEXT,ITEM],
	0x6f:['File Control Information (FCI) Template',BINARY,TEMPLATE],
	0x70:['Record Template',BINARY,TEMPLATE],
	0x77:['Response Message Template Format 2',BINARY,ITEM],
	0x80:['Response Message Template Format 1',BINARY,ITEM],
	0x82:['Application Interchange Profile',BINARY,ITEM],
	0x83:['Command Template',BER_TLV,ITEM],
	0x84:['DF Name',MIXED,ITEM],
	0x86:['Issuer Script Command',BER_TLV,ITEM],
	0x87:['Application Priority Indicator',BER_TLV,ITEM],
	0x88:['Short File Identifier',BINARY,ITEM],
	0x8a:['Authorisation Response Code',BINARY,VALUE],
	0x8c:['Card Risk Management Data Object List 1 (CDOL1)',BINARY,TEMPLATE],
	0x8d:['Card Risk Management Data Object List 2 (CDOL2)',BINARY,TEMPLATE],
	0x8e:['Cardholder Verification Method (CVM) List',BINARY,ITEM],
	0x8f:['Certification Authority Public Key Index',BINARY,ITEM],
	0x92:['Issuer Public Key Remainder',BINARY,ITEM],
	0x93:['Signed Static Application Data',BINARY,ITEM],
	0x94:['Application File Locator',BINARY,ITEM],
	0x95:['Terminal Verification Results',BINARY,VALUE],
	0x97:['Transaction Certificate Data Object List (TDOL)',BER_TLV,ITEM],
	0x9a:['Transaction Date',BINARY,VALUE],
	0x9c:['Transaction Type',BINARY,VALUE],
	0x9d:['Directory Definition File',BINARY,ITEM],
	0x9f02:['Amount, Authorised (Numeric)',BINARY,VALUE],
	0x9f03:['Amount, Other (Numeric)',BINARY,VALUE],
	0x9f04:['Amount, Other (Binary)',BINARY,VALUE],
	0x9f05:['Application Discretionary Data',BINARY,ITEM],
	0x9f07:['Application Usage Control',BINARY,ITEM],
	0x9f08:['Application Version Number',BINARY,ITEM],
	0x9f0d:['Issuer Action Code - Default',BINARY,ITEM],
	0x9f0e:['Issuer Action Code - Denial',BINARY,ITEM],
	0x9f0f:['Issuer Action Code - Online',BINARY,ITEM],
	0x9f11:['Issuer Code Table Index',BINARY,ITEM],
	0x9f12:['Application Preferred Name',TEXT,ITEM],
	0x9f1a:['Terminal Country Code',BINARY,VALUE],
	0x9f1f:['Track 1 Discretionary Data',TEXT,ITEM],
	0x9f20:['Track 2 Discretionary Data',TEXT,ITEM],
	0x9f26:['Application Cryptogram',BINARY,ITEM],
	0x9f32:['Issuer Public Key Exponent',BINARY,ITEM],
	0x9f36:['Application Transaction Counter',BINARY,ITEM],
	0x9f37:['Unpredictable Number',BINARY,VALUE],
	0x9f38:['Processing Options Data Object List (PDOL)',BINARY,TEMPLATE],
	0x9f42:['Application Currency Code',NUMERIC,ITEM],
	0x9f44:['Application Currency Exponent',NUMERIC,ITEM],
	0x9f4a:['Static Data Authentication Tag List',BINARY,ITEM],
	0x9f4d:['Log Entry',BINARY,ITEM],
	0x9f66:['Card Production Life Cycle',BINARY,ITEM],
	0xa5:['Proprietary Information',BINARY,TEMPLATE],
	0xbf0c:['File Control Information (FCI) Issuer Discretionary Data',BER_TLV,TEMPLATE],
*/

type TLV struct {
	Tag      []byte
	Value    []byte
	Children []*TLV
}

type Codec struct {
	EndMark []byte // For complex tags
}

const complexBit = 1 << 5

var (
	GenericCodec = Codec{EndMark: []byte{0x00, 0x00}}
	Arcus2Codec  = Codec{EndMark: []byte{0xD1}}
)

func (codec *Codec) PutValLen(buf []byte, x int) int {
	if x < 0x80 {
		buf[0] = byte(x)
		return 1
	}
	i := 1
	for x >= 0x80 {
		buf[i] = byte(x)
		x >>= 8
		i++
	}
	buf[0] = byte(0x7F + i)
	return i
}

func (codec *Codec) ValLen(buf []byte) (int, int, error) {
	if len(buf) == 0 {
		return 0, 0, errors.New("tag buffer too small (L1)")
	}
	if buf[0] < 0x80 {
		return int(buf[0]), 1, nil
	}
	lenbytes := buf[0] - 0x80
	if lenbytes == 0 { // Complex TLV
		return -1, 1, nil
	}
	if lenbytes > 8 {
		return 0, 0, errors.New("invalid tag length")
	}
	if len(buf) < int(lenbytes)+1 {
		return 0, 0, errors.New("tag buffer too small (L2)")
	}
	var tmp [8]byte
	copy(tmp[8-lenbytes:], buf[1:1+lenbytes])
	return int(binary.BigEndian.Uint64(tmp[:])), int(lenbytes) + 1, nil
}

func (codec *Codec) Encode(t, v []byte) []byte {
	l := make([]byte, 9)
	n := codec.PutValLen(l, len(v))
	buf := make([]byte, 0, len(t)+n+len(v))
	buf = append(buf, t...)
	buf = append(buf, l[:n]...)
	buf = append(buf, v...)
	return buf
}

func (codec *Codec) Decode(buf []byte) (int, *TLV, error) {
	tlvSize := 0
	for {
		if len(buf) < 2 {
			return 0, nil, errors.New("tag buffer too small (T)")
		}
		if !bytes.HasPrefix(buf, codec.EndMark) {
			break
		}
		buf = buf[len(codec.EndMark):]
		tlvSize += len(codec.EndMark)
	}

	var tag []byte
	if buf[0]&0x1F == 0x1F {
		for i := 1; i < len(buf); i++ {
			if buf[i]&0x80 != 0x80 {
				tag = make([]byte, i+1)
				copy(tag, buf[0:])
				break
			}
		}
	} else {
		tag = []byte{buf[0]}
	}

	tagSz := len(tag)
	vlen, lenSz, err := codec.ValLen(buf[tagSz:])
	if err != nil {
		return 0, nil, err
	}

	voffs := tagSz + lenSz
	if vlen < 0 {
		tlvSize += voffs
	} else {
		tlvSize += voffs + vlen
	}
	if len(buf) < tlvSize {
		return 0, nil, errors.New("tag buffer too small (V)")
	}

	var val []byte
	if vlen > 0 {
		val = make([]byte, vlen)
		copy(val, buf[voffs:])
	}
	tlv := TLV{Tag: tag, Value: val}

	if vlen >= 0 {
		return tlvSize, &tlv, nil
	}

	cbuf := buf[tlvSize:]
	tlv.Children = make([]*TLV, 0, 16)
	offs := 0
	for offs < len(cbuf) {
		if bytes.HasPrefix(cbuf[offs:], codec.EndMark) {
			return tlvSize + 1, &tlv, nil
		}
		subsz, subtlv, suberr := codec.Decode(cbuf[offs:])
		if suberr != nil {
			return 0, nil, errors.Wrap(suberr, "sub-tlv parse error")
		}
		tlv.Children = append(tlv.Children, subtlv)
		tlvSize += subsz
		offs += subsz
	}
	return 0, nil, errors.New("comlex tlv end marker missing")
}
