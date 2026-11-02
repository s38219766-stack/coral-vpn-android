package ct2

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

// Мутации корректного ClientHello и случайные байты: Accept не должен зависать ни на одном входе.
func TestAcceptNeverHangs(t *testing.T) {
	cc, _, _ := configs(t)
	base, _, _ := buildHello(cc, "www.yandex.ru")
	sk := newKey(t)
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var data []byte
		switch r.Intn(3) {
		case 0:
			data = append([]byte{}, base...)
			for k := 0; k <= r.Intn(6); k++ {
				data[r.Intn(len(data))] = byte(r.Intn(256))
			}
		case 1:
			data = append([]byte{}, base[:r.Intn(len(base))]...)
		default:
			data = make([]byte, r.Intn(200))
			r.Read(data)
			if len(data) > 5 && r.Intn(2) == 0 {
				data[0], data[1] = 0x16, 3
			}
		}
		done := make(chan struct{})
		go func() {
			sc := &Config{Static: sk, Allowed: func([]byte) bool { return true }}
			sc.SetReplayCache(NewReplayCache())
			Accept(&memConn{r: bytes.NewReader(data)}, sc, &Fallback{})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("Accept hung on input #%d (len %d): %x", i, len(data), data[:min(len(data), 64)])
		}
	}
}
