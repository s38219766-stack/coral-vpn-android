package ct2

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLS-несущий слой. Клиент шлёт настоящий по виду ClientHello Chrome (uTLS), в котором:
//   - эфемерный ключ рукопожатия лежит в штатном key_share X25519 (там и положено быть такому ключу);
//   - остальное сообщение 1 (зашифрованные 80 байт, похожие на случайные) лежит в начале GREASE-расширения ECH
//     (Chrome шлёт его с 144–240 случайными байтами);
//   - random ClientHello служит солью рукопожатия.
// Сервер отвечает ServerHello (ключ эфемерный в key_share) и ChangeCipherSpec, потом запись application data с сообщением 2 и
// случайным «хвостом». Дальше все записи ct2 идут как записи TLS application data. Любой чужой (проба, сканер, ошибка в проверке)
// получает настоящий сайт: соединение передаётся резервному адресу вместе с уже прочитанными байтами.

const (
	recHandshake = 0x16
	recCCS       = 0x14
	recAppData   = 0x17
	maxRecord    = 16384
)

var (
	ErrFallback = errors.New("ct2: connection handed to fallback")
	ErrNoSpace  = errors.New("ct2: client hello has no room for handshake")
)

// ChromeSigAlgs — список алгоритмов подписи, который шлёт актуальный Chrome. Профиль uTLS отстаёт от свежих версий браузера, и
// именно здесь отпечаток JA4 расходился с настоящим Chrome 151 (добавлены ML-DSA). Список обновляется по сравнению с установленным
// Chrome: `CT2_CHROME=1 go test -run CompareWithRealChrome -v`.
var ChromeSigAlgs = []utls.SignatureScheme{0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}

func prologueTLS(random []byte) []byte { return append([]byte("coral-ct2/1/tls"), random...) }

// ---------------- клиент ----------------

// buildHello возвращает полную запись TLS с ClientHello и состояние рукопожатия.
func buildHello(cfg *Config, sni string) ([]byte, func(m2 []byte) (*Conn, error), error) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto) // порядок расширений перемешан заново при каждом вызове, как у Chrome
	if err != nil {
		return nil, nil, err
	}
	for _, e := range spec.Extensions {
		if sa, ok := e.(*utls.SignatureAlgorithmsExtension); ok && len(ChromeSigAlgs) > 0 {
			sa.SupportedSignatureAlgorithms = ChromeSigAlgs
		}
	}
	u := utls.UClient(c1, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloCustom)
	if err := u.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	if err := u.BuildHandshakeState(); err != nil {
		return nil, nil, err
	}
	raw := append([]byte(nil), u.HandshakeState.Hello.Raw...)
	h, err := parseHello(raw)
	if err != nil || !h.usable() {
		return nil, nil, ErrNoSpace
	}
	if _, err := io.ReadFull(cfg.rng(), h.random); err != nil {
		return nil, nil, err
	}
	var rb [4]byte
	io.ReadFull(cfg.rng(), rb[:])
	m1, hs, err := cfg.initiate(prologueTLS(h.random), 0, rb[:])
	if err != nil {
		return nil, nil, err
	}
	copy(h.keyShare, m1[:32])
	copy(h.echPayload, m1[32:])
	rec := append([]byte{recHandshake, 3, 1, byte(len(raw) >> 8), byte(len(raw))}, raw...)
	done := func(m2 []byte) (*Conn, error) {
		send, recv, _, err := finish(hs, m2)
		if err != nil {
			return nil, err
		}
		return newConn(nil, send, recv, cfg, hs.PeerStatic()), nil
	}
	return rec, done, nil
}

// DialTLS выполняет рукопожатие клиента поверх c, маскируясь под обращение браузера к сайту sni.
func DialTLS(c net.Conn, cfg *Config, sni string) (*Conn, error) {
	rec, done, err := buildHello(cfg, sni)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(rec); err != nil {
		return nil, err
	}
	// ServerHello
	sh, err := readRecord(c, recHandshake)
	if err != nil {
		return nil, err
	}
	e2, err := parseServerHelloKey(sh)
	if err != nil {
		return nil, err
	}
	if _, err := readRecord(c, recCCS); err != nil {
		return nil, err
	}
	fl, err := readRecord(c, recAppData)
	if err != nil || len(fl) < msg2Len-32 {
		return nil, ErrHandshake
	}
	cn, err := done(append(append([]byte{}, e2...), fl[:msg2Len-32]...))
	if err != nil {
		return nil, err
	}
	cn.rw = &tlsFramer{c: c}
	return cn, nil
}

func readRecord(c io.Reader, want byte) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(h[3:]))
	if h[0] != want || h[1] != 3 || l == 0 || l > maxRecord+256 {
		return nil, ErrHandshake
	}
	b := make([]byte, l)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

// parseServerHelloKey достаёт 32-байтный ключ X25519 из key_share ServerHello.
func parseServerHelloKey(b []byte) ([]byte, error) {
	if len(b) < 4+2+32+1 || b[0] != 2 || int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b)-4 {
		return nil, ErrHandshake
	}
	b = b[4:]
	sl := int(b[34])
	p := 35 + sl + 3
	if p+2 > len(b) {
		return nil, ErrHandshake
	}
	el := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if p+el != len(b) {
		return nil, ErrHandshake
	}
	e := b[p:]
	for len(e) >= 4 {
		t, l := int(binary.BigEndian.Uint16(e)), int(binary.BigEndian.Uint16(e[2:]))
		if 4+l > len(e) {
			return nil, ErrHandshake
		}
		if t == extKeyShare && l == 36 && binary.BigEndian.Uint16(e[4:]) == groupX25519 && binary.BigEndian.Uint16(e[6:]) == 32 {
			return e[8 : 8+32], nil
		}
		e = e[4+l:]
	}
	return nil, ErrHandshake
}

// ---------------- сервер ----------------

// Fallback решает, куда передать «чужое» соединение. Dest получает имя сайта из ClientHello (может быть пустым).
type Fallback struct {
	Dest        func(sni string) string
	DialTimeout time.Duration
	IdleTimeout time.Duration
	MaxConns    int // сколько резервных соединений держим одновременно (0 — без ограничения); лишние просто закрываются

	once sync.Once
	sem  chan struct{}
}

// FlightRange — границы случайной длины «зашифрованной части» ответа сервера (как у настоящего сервера с цепочкой сертификатов).
var FlightLo, FlightHi = 1200, 3600

// Accept обслуживает входящее соединение. Если клиент свой, возвращает защищённое соединение. Если нет, передаёт соединение
// резервному сайту, ждёт его завершения и возвращает ErrFallback: вызывающий просто закрывает соединение.
func Accept(c net.Conn, cfg *Config, fb *Fallback) (*Conn, error) {
	rec, tlsOK := readFirst(c)
	c.SetReadDeadline(time.Time{})
	if !tlsOK {
		fb.run(c, rec, "")
		return nil, ErrFallback
	}
	raw := rec[5:]
	h, err := parseHello(raw)
	if err != nil || !h.usable() {
		fb.run(c, rec, sniOf(raw))
		return nil, ErrFallback
	}
	m1 := append(append([]byte{}, h.keyShare...), h.echPayload[:echBlobLen]...)
	if cfg.Limiter != nil {
		release, ok := cfg.Limiter.Allow(remoteIP(c))
		if !ok {
			fb.run(c, rec, h.sni)
			return nil, ErrFallback
		}
		defer release()
	}
	hs, _, cpub, err := cfg.respond(prologueTLS(h.random), m1)
	if err != nil {
		if cfg.Limiter != nil {
			cfg.Limiter.Fail(remoteIP(c))
		}
		fb.run(c, rec, h.sni)
		return nil, ErrFallback
	}
	var rb [6]byte
	if _, err := io.ReadFull(cfg.rng(), rb[:]); err != nil {
		return nil, err
	}
	m2, recv, send, err := cfg.reply(hs, 0, rb[:4])
	if err != nil {
		fb.run(c, rec, h.sni)
		return nil, ErrFallback
	}
	flight := buildServerFlight(cfg, h.sid, m2)
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = c.Write(flight)
	c.SetWriteDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	return newConn(&tlsFramer{c: c}, send, recv, cfg, cpub), nil
}

func sniOf(raw []byte) string {
	if h, err := parseHello(raw); err == nil {
		return h.sni
	}
	return ""
}

// buildServerFlight — ServerHello (ключ эфемерный в key_share), ChangeCipherSpec и запись application data: сообщение 2 + случайный хвост.
func buildServerFlight(cfg *Config, sid, m2 []byte) []byte {
	rng := cfg.rng()
	var exts []byte
	exts = append(exts, 0, 0x2b, 0, 2, 3, 4)
	exts = append(exts, 0, 0x33, 0, 36, 0, 0x1d, 0, 32)
	exts = append(exts, m2[:32]...)
	body := []byte{3, 3}
	rnd := make([]byte, 32)
	io.ReadFull(rng, rnd)
	body = append(body, rnd...)
	body = append(body, byte(len(sid)))
	body = append(body, sid...)
	body = append(body, 0x13, 0x01, 0)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	out := append([]byte{recHandshake, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	out = append(out, recCCS, 3, 3, 0, 1, 1)
	var r [2]byte
	io.ReadFull(rng, r[:])
	n := FlightLo + int(binary.BigEndian.Uint16(r[:]))%(FlightHi-FlightLo+1)
	if n < msg2Len-32 {
		n = msg2Len - 32
	}
	data := make([]byte, n)
	copy(data, m2[32:])
	io.ReadFull(rng, data[msg2Len-32:])
	return append(append(out, recAppData, 3, 3, byte(n>>8), byte(n)), data...)
}

// readFirst читает первую запись TLS. Если пришло что-то другое, отдаёт то, что есть (проба ждёт ответа).
func readFirst(c net.Conn) (rec []byte, ok bool) {
	buf := make([]byte, 5)
	n := 0
	c.SetReadDeadline(time.Now().Add(8 * time.Second))
	for n < 5 {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return buf[:n], false
		}
		if n < 5 {
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
	}
	if buf[0] != recHandshake || buf[1] != 3 {
		return buf, false
	}
	l := int(binary.BigEndian.Uint16(buf[3:]))
	if l < 40 || l > maxRecord {
		return buf, false
	}
	rest := make([]byte, l)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := io.ReadFull(c, rest)
	if err != nil {
		return append(buf, rest[:m]...), false
	}
	return append(buf, rest...), true
}

// run передаёт соединение настоящему сайту: уже прочитанные байты уходят первыми, дальше копируем в обе стороны.
func (f *Fallback) run(c net.Conn, first []byte, sni string) {
	dest := ""
	if f != nil && f.Dest != nil {
		dest = f.Dest(sni)
	}
	if dest == "" {
		return
	}
	if f.MaxConns > 0 {
		f.once.Do(func() { f.sem = make(chan struct{}, f.MaxConns) })
		select {
		case f.sem <- struct{}{}:
			defer func() { <-f.sem }()
		default:
			return
		}
	}
	to := 5 * time.Second
	if f.DialTimeout > 0 {
		to = f.DialTimeout
	}
	up, err := net.DialTimeout("tcp", dest, to)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(first); err != nil {
		return
	}
	idle := 2 * time.Minute
	if f.IdleTimeout > 0 {
		idle = f.IdleTimeout
	}
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		dst.Close()
		src.Close()
	}
	wg.Add(2)
	go cp(up, c)
	go cp(c, up)
	wg.Wait()
}

// ---------------- записи TLS поверх потока ----------------

// tlsFramer оборачивает записи ct2 в записи TLS application data и снимает заголовки при чтении.
type tlsFramer struct {
	c   net.Conn
	rem int
}

func (t *tlsFramer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxRecord {
			n = maxRecord
		}
		buf := make([]byte, 5+n)
		buf[0], buf[1], buf[2] = recAppData, 3, 3
		binary.BigEndian.PutUint16(buf[3:], uint16(n))
		copy(buf[5:], p[:n])
		if _, err := t.c.Write(buf); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (t *tlsFramer) Read(p []byte) (int, error) {
	for t.rem == 0 {
		var h [5]byte
		if _, err := io.ReadFull(t.c, h[:]); err != nil {
			return 0, err
		}
		l := int(binary.BigEndian.Uint16(h[3:]))
		if h[0] != recAppData || h[1] != 3 || l == 0 || l > maxRecord+256 {
			return 0, ErrFrame
		}
		t.rem = l
	}
	if len(p) > t.rem {
		p = p[:t.rem]
	}
	n, err := t.c.Read(p)
	t.rem -= n
	return n, err
}

func (t *tlsFramer) Close() error { return t.c.Close() }

var _ = crand.Reader
