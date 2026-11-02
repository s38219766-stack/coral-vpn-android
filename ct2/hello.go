package ct2

import (
	"encoding/binary"
	"errors"
)

// Разбор и правка ClientHello. Формат проверяется строго: чужие данные не разбираем.

var errHello = errors.New("ct2: not a ClientHello")

const (
	extKeyShare = 0x0033
	extECH      = 0xfe0d
	extSNI      = 0x0000
	groupX25519 = 0x001d
	echBlobLen  = msg1Len - 32 // всё сообщение 1 кроме эфемерного ключа: enc(C) + enc(payload)
)

// helloInfo — места в сообщении ClientHello (без заголовка записи), куда мы кладём части рукопожатия.
type helloInfo struct {
	random     []byte // 32 байта (внутри raw)
	sid        []byte
	sni        string
	keyShare   []byte // 32 байта X25519 (внутри raw)
	echPayload []byte // полезная часть GREASE-ECH (внутри raw)
}

func parseHello(raw []byte) (*helloInfo, error) {
	if len(raw) < 4+2+32+1 || raw[0] != 1 {
		return nil, errHello
	}
	hl := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if hl+4 != len(raw) {
		return nil, errHello
	}
	b := raw[4:]
	h := &helloInfo{random: b[2:34]}
	sl := int(b[34])
	if sl != 32 || len(b) < 35+sl+2 {
		return nil, errHello
	}
	h.sid = b[35 : 35+sl]
	p := 35 + sl
	p += 2 + int(binary.BigEndian.Uint16(b[p:]))
	if p+1 > len(b) {
		return nil, errHello
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil, errHello
	}
	el := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if p+el != len(b) {
		return nil, errHello
	}
	e := b[p:]
	for len(e) > 0 {
		if len(e) < 4 {
			return nil, errHello
		}
		t, l := int(binary.BigEndian.Uint16(e)), int(binary.BigEndian.Uint16(e[2:]))
		if 4+l > len(e) {
			return nil, errHello
		}
		d := e[4 : 4+l]
		switch t {
		case extSNI:
			if l >= 5 {
				if nl := int(binary.BigEndian.Uint16(d[3:])); 5+nl <= l {
					h.sni = string(d[5 : 5+nl])
				}
			}
		case extKeyShare:
			if l >= 2 && int(binary.BigEndian.Uint16(d))+2 == l {
				for q := 2; q+4 <= l; {
					g, kl := int(binary.BigEndian.Uint16(d[q:])), int(binary.BigEndian.Uint16(d[q+2:]))
					if q+4+kl > l {
						break
					}
					if g == groupX25519 && kl == 32 && h.keyShare == nil {
						h.keyShare = d[q+4 : q+4+32]
					}
					q += 4 + kl
				}
			}
		case extECH:
			// ECHClientHello (внешний): тип(1) kdf(2) aead(2) config_id(1) длина enc(2) enc payload_len(2) payload
			if l >= 8 && d[0] == 0 {
				enc := int(binary.BigEndian.Uint16(d[6:]))
				if 8+enc+2 <= l {
					pl := int(binary.BigEndian.Uint16(d[8+enc:]))
					if 8+enc+2+pl == l {
						h.echPayload = d[8+enc+2:]
					}
				}
			}
		}
		e = e[4+l:]
	}
	return h, nil
}

// usable сообщает, что в ClientHello есть место для рукопожатия.
func (h *helloInfo) usable() bool { return h.keyShare != nil && len(h.echPayload) >= echBlobLen }
