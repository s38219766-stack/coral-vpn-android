package ct2

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// Формат записи после рукопожатия: [длина тела, зашифрована: 2+16 байт][тело, зашифровано: len+16 байт].
// Тело кадра: тип (1) | длина данных (2) | данные | дополнение.
const (
	frameHdr   = 3
	MaxData    = 15900                     // запись целиком (18+тело+16) должна помещаться в одну запись TLS (до 16384)
	MaxBody    = 16384 - lenBlock - tagLen // верхняя граница тела
	tagLen     = 16
	lenBlock   = 2 + tagLen
	defaultRek = uint64(1) << 20
)

const (
	frameData  byte = 0
	framePad   byte = 1
	framePing  byte = 2
	frameRekey byte = 3
	frameClose byte = 4
)

var (
	ErrAuth  = errors.New("ct2: record authentication failed")
	ErrFrame = errors.New("ct2: bad frame")
)

// Conn — защищённое соединение: Read/Write как у обычного потока, Close закрывает нижележащий транспорт.
type Conn struct {
	rw   io.ReadWriter
	cfg  *Config
	peer []byte
	pad  Padder // политика дополнения этого сеанса (случайный профиль, если не задан в Config)

	wmu    sync.Mutex
	send   *noise.CipherState
	frames uint64
	rekeyN uint64

	rmu  sync.Mutex
	recv *noise.CipherState
	left []byte
}

func newConn(rw io.ReadWriter, send, recv *noise.CipherState, cfg *Config, peer []byte) *Conn {
	n := cfg.RekeyFrames
	if n == 0 {
		n = defaultRek
	}
	pad := cfg.Padder
	if pad == nil {
		pad = NewRandomPadder(cfg.rng())
	}
	return &Conn{rw: rw, cfg: cfg, peer: append([]byte{}, peer...), pad: pad, send: send, recv: recv, rekeyN: n}
}

// PeerStatic — статический публичный ключ собеседника (для клиента это ключ сервера, для сервера — ключ пользователя).
func (c *Conn) PeerStatic() []byte { return c.peer }

func (c *Conn) writeFrame(typ byte, data []byte) error {
	pad := 0
	if typ == frameData || typ == framePad {
		pad = c.pad.Pad(len(data), c.cfg.rng())
	}
	body := make([]byte, frameHdr+len(data)+pad)
	body[0] = typ
	body[1], body[2] = byte(len(data)>>8), byte(len(data))
	copy(body[frameHdr:], data)
	if pad > 0 {
		io.ReadFull(c.cfg.rng(), body[frameHdr+len(data):])
	}
	l, err := c.send.Encrypt(nil, nil, []byte{byte(len(body) >> 8), byte(len(body))})
	if err != nil {
		return err
	}
	b, err := c.send.Encrypt(nil, nil, body)
	if err != nil {
		return err
	}
	_, err = c.rw.Write(append(l, b...))
	return err
}

// Write делит данные на кадры, каждый дополняется по политике Padder; ключи меняются через RekeyFrames кадров.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n := 0
	for len(p) > 0 || n == 0 {
		chunk := p
		if len(chunk) > MaxData {
			chunk = chunk[:MaxData]
		}
		if err := c.writeFrame(frameData, chunk); err != nil {
			return n, err
		}
		n += len(chunk)
		p = p[len(chunk):]
		c.frames++
		if c.frames >= c.rekeyN {
			if err := c.writeFrame(frameRekey, nil); err != nil {
				return n, err
			}
			c.send.Rekey()
			c.frames = 0
		}
		if len(p) == 0 {
			break
		}
	}
	return n, nil
}

// Ping отправляет пустой кадр-маячок (для имитации активности и проверки канала).
func (c *Conn) Ping() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeFrame(framePing, nil)
}

// Cover отправляет кадр, состоящий только из дополнения: заполняет паузы, чтобы трафик не «замолкал».
func (c *Conn) Cover(size int) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if size < 0 || size > MaxData {
		return ErrFrame
	}
	return c.writeFrame(framePad, make([]byte, size))
}

func (c *Conn) readFrame() (byte, []byte, error) {
	var lb [lenBlock]byte
	if _, err := io.ReadFull(c.rw, lb[:]); err != nil {
		return 0, nil, err
	}
	l, err := c.recv.Decrypt(nil, nil, lb[:])
	if err != nil {
		return 0, nil, ErrAuth
	}
	n := int(l[0])<<8 | int(l[1])
	if n < frameHdr || n > MaxBody {
		return 0, nil, ErrFrame
	}
	bb := make([]byte, n+tagLen)
	if _, err := io.ReadFull(c.rw, bb); err != nil {
		return 0, nil, err
	}
	body, err := c.recv.Decrypt(nil, nil, bb)
	if err != nil {
		return 0, nil, ErrAuth
	}
	dl := int(body[1])<<8 | int(body[2])
	if frameHdr+dl > len(body) || dl > MaxData {
		return 0, nil, ErrFrame
	}
	return body[0], body[frameHdr : frameHdr+dl], nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.left) == 0 {
		typ, data, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch typ {
		case frameData:
			c.left = data
		case framePad, framePing:
		case frameRekey:
			c.recv.Rekey()
		case frameClose:
			return 0, io.EOF
		default:
			return 0, ErrFrame
		}
	}
	n := copy(p, c.left)
	c.left = c.left[n:]
	return n, nil
}

// Close отправляет кадр завершения (не дольше 2 секунд и только если запись сейчас свободна) и закрывает нижележащий транспорт.
// Зависший собеседник не должен задерживать закрытие: иначе очистка отозванных сеансов могла бы застрять на одном соединении.
func (c *Conn) Close() error {
	if c.wmu.TryLock() {
		if d, ok := c.rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
			d.SetWriteDeadline(time.Now().Add(2 * time.Second))
		}
		c.writeFrame(frameClose, nil)
		c.wmu.Unlock()
	}
	if cl, ok := c.rw.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}
