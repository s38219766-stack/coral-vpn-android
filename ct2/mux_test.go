package ct2

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowConn добавляет задержку записи, не блокируя следующие записи (как настоящий канал: пакеты в пути одновременно).
type slowConn struct {
	net.Conn
	d  time.Duration
	q  chan slowItem
	mu sync.Mutex
}

type slowItem struct {
	at time.Time
	b  []byte
}

func newSlow(c net.Conn, d time.Duration) *slowConn {
	s := &slowConn{Conn: c, d: d, q: make(chan slowItem, 4096)}
	go func() {
		for it := range s.q {
			if w := time.Until(it.at); w > 0 {
				time.Sleep(w)
			}
			c.Write(it.b)
		}
	}()
	return s
}

func (s *slowConn) Write(p []byte) (int, error) {
	s.q <- slowItem{time.Now().Add(s.d), append([]byte{}, p...)}
	return len(p), nil
}

// muxServer поднимает сервер ct2 с эхо-потоками на localhost; delay — задержка в каждую сторону.
func muxServer(t testing.TB, sc *Config, delay time.Duration) (addr string, handshakes *atomic.Int32, stop func()) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handshakes = &atomic.Int32{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				var cc net.Conn = c
				if delay > 0 {
					cc = newSlow(c, delay)
				}
				cn, err := Accept(cc, sc, &Fallback{})
				if err != nil {
					c.Close()
					return
				}
				handshakes.Add(1)
				ServeMux(cn, func(st net.Conn) { io.Copy(st, st); st.Close() })
			}()
		}
	}()
	return l.Addr().String(), handshakes, func() { l.Close() }
}

func newPool(cc *Config, addr string, delay time.Duration, size int, dials *atomic.Int32) *Pool {
	return &Pool{Size: size, Dial: func() (*Conn, error) {
		dials.Add(1)
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		var c net.Conn = raw
		if delay > 0 {
			c = newSlow(raw, delay)
		}
		return DialTLS(c, cc, "www.yandex.ru")
	}}
}

func TestMuxEchoConcurrent(t *testing.T) {
	cc, sc, _ := configs(t)
	addr, _, stop := muxServer(t, sc, 0)
	defer stop()
	var dials atomic.Int32
	p := newPool(cc, addr, 0, 2, &dials)
	defer p.Close()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := p.Open()
			if err != nil {
				errs <- err.Error()
				return
			}
			defer st.Close()
			msg := make([]byte, 1+i*5000)
			rand.Read(msg)
			go st.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, msg) {
				errs <- "stream mismatch"
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if d := dials.Load(); d > 2 {
		t.Fatalf("40 streams made %d handshakes, want <= 2", d)
	}
}

func TestPoolRecoversAfterSessionDeath(t *testing.T) {
	cc, sc, _ := configs(t)
	addr, hs, stop := muxServer(t, sc, 0)
	defer stop()
	var dials atomic.Int32
	p := newPool(cc, addr, 0, 1, &dials)
	defer p.Close()
	echo := func() {
		st, err := p.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		st.Write([]byte("ping"))
		b := make([]byte, 4)
		if _, err := io.ReadFull(st, b); err != nil || string(b) != "ping" {
			t.Fatal("echo failed", err)
		}
	}
	echo()
	p.mu.Lock()
	for _, s := range p.sessions {
		s.Close()
	}
	p.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	echo()
	if dials.Load() != 2 || hs.Load() != 2 {
		t.Fatalf("expected a fresh handshake after death: dials=%d server=%d", dials.Load(), hs.Load())
	}
}

// Главное преимущество: поток на готовом сеансе стоит один круговой обход, новое соединение с рукопожатием — два.
func TestMuxFasterThanHandshakePerFlow(t *testing.T) {
	const delay = 40 * time.Millisecond
	cc, sc, _ := configs(t)
	sc.Limiter = nil
	addr, _, stop := muxServer(t, sc, delay)
	defer stop()
	var dials atomic.Int32
	p := newPool(cc, addr, delay, 1, &dials)
	defer p.Close()
	flow := func(open func() (net.Conn, error)) time.Duration {
		t0 := time.Now()
		st, err := open()
		if err != nil {
			t.Fatal(err)
		}
		st.Write([]byte("x"))
		b := make([]byte, 1)
		if _, err := io.ReadFull(st, b); err != nil {
			t.Fatal(err)
		}
		st.Close()
		return time.Since(t0)
	}
	flow(p.Open) // прогрев: рукопожатие сеанса
	var muxT, perT time.Duration
	for i := 0; i < 5; i++ {
		muxT += flow(p.Open)
		perT += flow(func() (net.Conn, error) {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			cn, err := DialTLS(newSlow(raw, delay), cc, "www.yandex.ru")
			if err != nil {
				return nil, err
			}
			return muxOne(cn), nil
		})
	}
	t.Logf("поток на готовом сеансе: %v, отдельное соединение с рукопожатием: %v (в среднем на запрос, односторонняя задержка %v)", muxT/5, perT/5, delay)
	if muxT*10 > perT*7 {
		t.Fatalf("мультиплексирование не дало выигрыша: %v против %v", muxT/5, perT/5)
	}
}

// muxOne открывает один поток поверх свежего сеанса (так выглядело бы соединение «одно на поток»).
func muxOne(cn *Conn) net.Conn {
	p := &Pool{Size: 1, Dial: func() (*Conn, error) { return cn, nil }}
	st, _ := p.Open()
	return st
}

// BenchmarkMuxThroughput: скорость одного потока на сеансе через TCP на localhost.
func BenchmarkMuxThroughput(b *testing.B) {
	cc, sc, _ := configs(b)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		cn, err := Accept(c, sc, &Fallback{})
		if err != nil {
			return
		}
		ServeMux(cn, func(st net.Conn) { io.Copy(io.Discard, st) })
	}()
	var dials atomic.Int32
	p := newPool(cc, l.Addr().String(), 0, 1, &dials)
	defer p.Close()
	st, err := p.Open()
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 1<<20)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(msg); err != nil {
			b.Fatal(err)
		}
	}
}

// Регрессия: поток на сервере не должен обрываться при сборке мусора (finalizer в smux, issue #997).
func TestMuxSurvivesGC(t *testing.T) {
	cc, sc, _ := configs(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan int64, 1)
	go func() {
		c, _ := l.Accept()
		cn, err := Accept(c, sc, &Fallback{})
		if err != nil {
			got <- -1
			return
		}
		ServeMux(cn, func(st net.Conn) {
			n, _ := io.Copy(io.Discard, st)
			got <- n
		})
	}()
	var dials atomic.Int32
	p := newPool(cc, l.Addr().String(), 0, 1, &dials)
	defer p.Close()
	st, err := p.Open()
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	msg := make([]byte, 1<<20)
	const total = 40
	for i := 0; i < total; i++ {
		if _, err := st.Write(msg); err != nil {
			t.Fatalf("write %d failed: %v", i, err)
		}
	}
	st.Close()
	close(stop)
	if n := <-got; n != int64(total)<<20 {
		t.Fatalf("server received %d bytes, want %d", n, int64(total)<<20)
	}
}

// Сервер недоступен: пока идёт неудачная попытка соединения, остальные потоки не должны стоять в очереди (раньше каждый ждал
// своей попытки под общей блокировкой), а после неудачи повторные попытки идут с паузой.
func TestPoolFailedDialDoesNotStallOthers(t *testing.T) {
	var dials atomic.Int32
	p := &Pool{Size: 2, Dial: func() (*Conn, error) {
		dials.Add(1)
		time.Sleep(300 * time.Millisecond)
		return nil, io.ErrUnexpectedEOF
	}}
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Open(); err == nil {
				t.Error("ожидали ошибку: сервер недоступен")
			}
		}()
	}
	wg.Wait()
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("25 потоков ждали %v: очередь на одной попытке", el)
	}
	if d := dials.Load(); d > 3 {
		t.Fatalf("25 потоков сделали %d попыток соединения, ожидали не больше 3", d)
	}
	// сразу после неудачи отказ мгновенный, без новой попытки
	t0 := time.Now()
	before := dials.Load()
	if _, err := p.Open(); err == nil || time.Since(t0) > 100*time.Millisecond || dials.Load() != before {
		t.Fatalf("после неудачи ожидали мгновенный отказ без новой попытки (ждали %v, попыток +%d)", time.Since(t0), dials.Load()-before)
	}
}

// После восстановления сети сеанс создаётся заново, как только пройдёт пауза.
func TestPoolRecoversAfterOutage(t *testing.T) {
	cc, sc, _ := configs(t)
	addr, _, stop := muxServer(t, sc, 0)
	defer stop()
	var down atomic.Bool
	down.Store(true)
	p := &Pool{Size: 1, Dial: func() (*Conn, error) {
		if down.Load() {
			return nil, io.ErrUnexpectedEOF
		}
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return DialTLS(raw, cc, "www.yandex.ru")
	}}
	defer p.Close()
	if _, err := p.Open(); err == nil {
		t.Fatal("в аварии ожидали ошибку")
	}
	down.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := p.Open()
		if err == nil {
			st.Write([]byte("ping"))
			buf := make([]byte, 4)
			if _, err := io.ReadFull(st, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("эхо после восстановления: %v %q", err, buf)
			}
			st.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("сеанс не восстановился за 5 с: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Пока создаётся новый сеанс, потоки на уже живом сеансе не ждут.
func TestPoolLiveSessionNotBlockedByDialing(t *testing.T) {
	cc, sc, _ := configs(t)
	addr, _, stop := muxServer(t, sc, 0)
	defer stop()
	var slow atomic.Bool
	p := &Pool{Size: 2, Spread: 1, Dial: func() (*Conn, error) {
		if slow.Load() {
			time.Sleep(800 * time.Millisecond)
		}
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return DialTLS(raw, cc, "www.yandex.ru")
	}}
	defer p.Close()
	first, err := p.Open() // живой сеанс с одним потоком; Spread=1 → следующий поток захочет второй сеанс
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	slow.Store(true)
	go func() { p.Open() }() // запускает медленное создание второго сеанса
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	st, err := p.Open() // идёт параллельно создаваемому: должен взять живой сеанс сразу
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if el := time.Since(t0); el > 300*time.Millisecond {
		t.Fatalf("поток на живом сеансе ждал %v, пока создаётся второй", el)
	}
}
