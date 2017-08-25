package bertlv

import (
	"encoding/binary"
	"errors"
)

/*
	Possible tag explanation (NOT CONFIRMED!)
	Alos look at https://www.eftlab.co.uk/index.php/site-map/knowledge-base/145-emv-nfc-tags

	0x4f:['Application Identifier (AID)',BINARY,ITEM],
	0x50:['Application Label',TEXT,ITEM],
	0x57:['Track 2 Equivalent Data',BINARY,ITEM],
	0x5a:['Application Primary Account Number (PAN)',NUMERIC,ITEM],
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
	0x93:['Signed Static Application Data',BINARY,ITEM],
	0x94:['Application File Locator',BINARY,ITEM],
	0x95:['Terminal Verification Results',BINARY,VALUE],
	0x97:['Transaction Certificate Data Object List (TDOL)',BER_TLV,ITEM],
	0x9c:['Transaction Type',BINARY,VALUE],
	0x9d:['Directory Definition File',BINARY,ITEM],
	0xa5:['Proprietary Information',BINARY,TEMPLATE],
	0x5f20:['Cardholder Name',TEXT,ITEM],
	0x5f24:['Application Expiration Date YYMMDD',NUMERIC,ITEM],
	0x5f25:['Application Effective Date YYMMDD',NUMERIC,ITEM],
	0x5f28:['Issuer Country Code',NUMERIC,ITEM],
	0x5f2a:['Transaction Currency Code',BINARY,VALUE],
	0x5f2d:['Language Preference',TEXT,ITEM],
	0x5f30:['Service Code',NUMERIC,ITEM],
	0x5f34:['Application Primary Account Number (PAN) Sequence Number',NUMERIC,ITEM],
	0x5f50:['Issuer URL',TEXT,ITEM],
	0x92:['Issuer Public Key Remainder',BINARY,ITEM],
	0x9a:['Transaction Date',BINARY,VALUE],
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
	0xbf0c:['File Control Information (FCI) Issuer Discretionary Data',BER_TLV,TEMPLATE],
*/

// Returns: <full length of tlv frame>, <tag number>, <value bytes>, <error>
func Decode(p []byte) (fl int, t []byte, v []byte, err error) {
	if len(p) < 2 {
		err = errors.New("Data too short!")
		return
	}

	if p[0]&0x1F == 0x1F {
		for i := 1; i < len(p); i++ {
			if p[i]&0x80 == 0 {
				t = p[0:(i + 1)]
				break
			}
		}
	} else {
		t = p[0:1]
	}
	offs := len(t)
	if offs == 0 || offs == len(p) {
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
	fl = offs + int(l)
	v = p[offs:fl]
	return
}
