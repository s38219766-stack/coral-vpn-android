// Пакет ct2 — прототип транспорта Coral Transport v2: рукопожатие Noise_IK (X25519, ChaCha20-Poly1305, BLAKE2s)
// с прямой секретностью, кадры с шифрованной длиной и дополнением, смена ключей на лету.
// Собственной криптографии здесь нет: все примитивы стандартные (Noise, x/crypto). Наше — формат кадров, маскировка и политика.
package ct2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

const (
	Version     = 1
	saltLen     = 16
	msg1Len     = 32 + 48 + 32 // e + enc(s) + enc(payload 16)
	msg2Len     = 32 + 24      // e + enc(payload 8)
	payload1Len = 16
	payload2Len = 8
	maxHsPad    = 255
	// ClockSkew — допустимое расхождение часов клиента и сервера в рукопожатии.
	ClockSkew = 120 * time.Second
)

var (
	ErrHandshake    = errors.New("ct2: handshake failed")
	ErrUnauthorized = errors.New("ct2: client not allowed")
	ErrReplay       = errors.New("ct2: replayed handshake")
	ErrStale        = errors.New("ct2: handshake timestamp out of window")

	suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
)

// Config описывает одну сторону соединения.
type Config struct {
	Static    noise.DHKey                 // статический ключ этой стороны
	ServerPub []byte                      // клиент: статический публичный ключ сервера (ключ раздаётся с подпиской)
	Allowed   func(clientPub []byte) bool // сервер: разрешён ли этот клиент
	Padder    Padder                      // политика дополнения кадров (по умолчанию BucketPadder)
	Now       func() time.Time            // часы (для тестов)
	Rand      io.Reader                   // источник случайных байтов (для тестов)
	Limiter   *Limiter                    // сервер (TLS-режим): ограничитель рукопожатий; nil — без ограничений
	// RekeyFrames — через сколько кадров менять ключи (0 — по умолчанию 1<<20).
	RekeyFrames uint64

	replay *replayCache
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) rng() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Config) padder() Padder {
	if c.Padder != nil {
		return c.Padder
	}
	return DefaultPadder
}

// replayCache помнит эфемерные ключи клиентов за окно времени: повтор рукопожатия отклоняется.
type replayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

func NewReplayCache() *replayCache { return &replayCache{seen: map[[32]byte]time.Time{}} }

func (r *replayCache) check(e []byte, now time.Time) bool {
	var k [32]byte
	copy(k[:], e)
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, t := range r.seen {
		if now.Sub(t) > 2*ClockSkew {
			delete(r.seen, key)
		}
	}
	if _, dup := r.seen[k]; dup {
		return false
	}
	if len(r.seen) > 200000 { // защита памяти: при переполнении лучше отказать, чем вырасти
		return false
	}
	r.seen[k] = now
	return true
}

// SetReplayCache задаёт общий кэш повторов сервера (один на все соединения).
func (c *Config) SetReplayCache(r *replayCache) { c.replay = r }

func prologue(salt []byte) []byte { return append([]byte("coral-ct2/1"), salt...) }

// maskStream — потоковая маска поверх рукопожатия: прячет структуру ключей X25519 (старший бит и т. п.). Не защита, а маскировка:
// ключ маски выводится из публичного ключа сервера и соли соединения.
func maskStream(serverPub, salt []byte, dir string) *chacha20.Cipher {
	k := blake2s.Sum256(append([]byte("ct2-mask-"+dir), serverPub...))
	c, _ := chacha20.NewUnauthenticatedCipher(k[:], salt[:12])
	return c
}

func xorIn(c *chacha20.Cipher, b []byte) { c.XORKeyStream(b, b) }

// ---- ядро рукопожатия: одни и те же проверки для «сырого» и TLS-режимов ----

func newPayload1(now time.Time, padLen int, rnd4 []byte) []byte {
	p := make([]byte, payload1Len)
	p[0] = Version
	binary.BigEndian.PutUint64(p[2:10], uint64(now.Unix()))
	binary.BigEndian.PutUint16(p[10:12], uint16(padLen))
	copy(p[12:16], rnd4)
	return p
}

// initiate строит сообщение 1 (e ‖ enc(C) ‖ enc(payload)) и состояние рукопожатия клиента.
func (c *Config) initiate(pro []byte, padLen int, rnd4 []byte) ([]byte, *noise.HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Random: c.rng(), Pattern: noise.HandshakeIK, Initiator: true, Prologue: pro,
		StaticKeypair: c.Static, PeerStatic: c.ServerPub,
	})
	if err != nil {
		return nil, nil, err
	}
	m1, _, _, err := hs.WriteMessage(nil, newPayload1(c.now(), padLen, rnd4))
	if err != nil || len(m1) != msg1Len {
		return nil, nil, ErrHandshake
	}
	return m1, hs, nil
}

// respond разбирает сообщение 1 и выполняет все проверки сервера. Возвращает длину дополнения клиента.
func (c *Config) respond(pro, m1 []byte) (*noise.HandshakeState, int, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Random: c.rng(), Pattern: noise.HandshakeIK, Initiator: false, Prologue: pro, StaticKeypair: c.Static,
	})
	if err != nil {
		return nil, 0, nil, err
	}
	p1, _, _, err := hs.ReadMessage(nil, m1)
	if err != nil || len(p1) != payload1Len || p1[0] != Version {
		return nil, 0, nil, ErrHandshake
	}
	cpub := hs.PeerStatic()
	if c.Allowed == nil || !c.Allowed(cpub) {
		return nil, 0, nil, ErrUnauthorized
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(p1[2:10])), 0)
	if d := c.now().Sub(ts); d > ClockSkew || d < -ClockSkew {
		return nil, 0, nil, ErrStale
	}
	if c.replay != nil && !c.replay.check(m1[:32], c.now()) {
		return nil, 0, nil, ErrReplay
	}
	padLen := int(binary.BigEndian.Uint16(p1[10:12]))
	if padLen > maxHsPad {
		return nil, 0, nil, ErrHandshake
	}
	return hs, padLen, cpub, nil
}

// reply строит сообщение 2 и возвращает шифры транспорта (приём, отправка) сервера.
func (c *Config) reply(hs *noise.HandshakeState, padLen int, rnd4 []byte) (m2 []byte, recv, send *noise.CipherState, err error) {
	p2 := make([]byte, payload2Len)
	p2[0] = Version
	binary.BigEndian.PutUint16(p2[2:4], uint16(padLen))
	copy(p2[4:8], rnd4)
	m2, cs0, cs1, err := hs.WriteMessage(nil, p2)
	if err != nil || len(m2) != msg2Len {
		return nil, nil, nil, ErrHandshake
	}
	return m2, cs0, cs1, nil
}

// finish разбирает сообщение 2 на клиенте и возвращает шифры (отправка, приём) и длину дополнения сервера.
func finish(hs *noise.HandshakeState, m2 []byte) (send, recv *noise.CipherState, padLen int, err error) {
	p2, cs0, cs1, err := hs.ReadMessage(nil, m2)
	if err != nil || len(p2) != payload2Len || p2[0] != Version {
		return nil, nil, 0, ErrHandshake
	}
	padLen = int(binary.BigEndian.Uint16(p2[2:4]))
	if padLen > maxHsPad {
		return nil, nil, 0, ErrHandshake
	}
	return cs0, cs1, padLen, nil
}

// Client выполняет рукопожатие клиента поверх rw (сырой режим с маской) и возвращает защищённое соединение.
func Client(rw io.ReadWriter, cfg *Config) (*Conn, error) {
	rng := cfg.rng()
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rng, salt); err != nil {
		return nil, err
	}
	var rb [5]byte
	if _, err := io.ReadFull(rng, rb[:]); err != nil {
		return nil, err
	}
	padLen := int(rb[0]) % (maxHsPad + 1)
	m1, hs, err := cfg.initiate(prologue(salt), padLen, rb[1:5])
	if err != nil {
		return nil, err
	}
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(rng, pad); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, m1...), pad...)
	xorIn(maskStream(cfg.ServerPub, salt, "c2s"), out)
	if _, err := rw.Write(append(append([]byte{}, salt...), out...)); err != nil {
		return nil, err
	}
	m2 := make([]byte, msg2Len)
	if _, err := io.ReadFull(rw, m2); err != nil {
		return nil, err
	}
	xorIn(maskStream(cfg.ServerPub, salt, "s2c"), m2)
	send, recv, sp, err := finish(hs, m2)
	if err != nil {
		return nil, err
	}
	if sp > 0 {
		if _, err := io.CopyN(io.Discard, rw, int64(sp)); err != nil {
			return nil, err
		}
	}
	return newConn(rw, send, recv, cfg, hs.PeerStatic()), nil
}

// Server выполняет рукопожатие сервера (сырой режим). При любой ошибке соединение нужно вести как с обычным посетителем сайта
// (резервный ответ): наружу не отправляется ничего, что отличало бы причины отказа.
func Server(rw io.ReadWriter, cfg *Config) (*Conn, error) {
	buf := make([]byte, saltLen+msg1Len)
	if _, err := io.ReadFull(rw, buf); err != nil {
		return nil, err
	}
	salt, m1 := buf[:saltLen], buf[saltLen:]
	xorIn(maskStream(cfg.Static.Public, salt, "c2s"), m1)
	hs, clientPad, cpub, err := cfg.respond(prologue(salt), m1)
	if err != nil {
		return nil, err
	}
	if clientPad > 0 {
		if _, err := io.CopyN(io.Discard, rw, int64(clientPad)); err != nil {
			return nil, err
		}
	}
	var rb [5]byte
	if _, err := io.ReadFull(cfg.rng(), rb[:]); err != nil {
		return nil, err
	}
	padLen := int(rb[0]) % (maxHsPad + 1)
	m2, recv, send, err := cfg.reply(hs, padLen, rb[1:5])
	if err != nil {
		return nil, err
	}
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(cfg.rng(), pad); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, m2...), pad...)
	xorIn(maskStream(cfg.Static.Public, salt, "s2c"), out)
	if _, err := rw.Write(out); err != nil {
		return nil, err
	}
	return newConn(rw, send, recv, cfg, cpub), nil
}

// KeyFromPrivate восстанавливает пару ключей X25519 из приватного ключа (32 байта).
func KeyFromPrivate(priv []byte) (noise.DHKey, error) {
	if len(priv) != 32 {
		return noise.DHKey{}, errors.New("ct2: private key must be 32 bytes")
	}
	pub, err := noise.DH25519.DH(priv, basepoint[:])
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: append([]byte{}, priv...), Public: pub}, nil
}

var basepoint = [32]byte{9}
