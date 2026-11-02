package ct2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countListener считает принятые соединения: так видно, что проба действительно дошла до настоящего сайта.
type countListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

// decoy — настоящий TLS-сайт: пробы должны получать именно его.
func decoy(t testing.TB) (addr string, hits *atomic.Int32, stop func()) {
	hits = &atomic.Int32{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "real decoy site") }))
	s.Listener = countListener{s.Listener, hits}
	s.StartTLS()
	return strings.TrimPrefix(s.URL, "https://"), hits, s.Close
}

func carrierPair(t testing.TB, cc, sc *Config, fb *Fallback) (cli, srv *Conn, cerr, serr error) {
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		srv, serr = Accept(b, sc, fb)
		if serr != nil {
			b.Close()
		}
		close(done)
	}()
	cli, cerr = DialTLS(a, cc, "www.yandex.ru")
	if cerr != nil {
		a.Close()
	}
	<-done
	return
}

func TestCarrierRoundTrip(t *testing.T) {
	cc, sc, ck := configs(t)
	cli, srv, ce, se := carrierPair(t, cc, sc, &Fallback{})
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	if !bytes.Equal(srv.PeerStatic(), ck.Public) {
		t.Fatal("peer key mismatch")
	}
	for _, n := range []int{1, 1000, 15900, 15901, 70000} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 7)
		}
		go cli.Write(msg)
		got := make([]byte, n)
		if _, err := io.ReadFull(srv, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("c2s n=%d: %v", n, err)
		}
		go srv.Write(msg)
		if _, err := io.ReadFull(cli, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("s2c n=%d: %v", n, err)
		}
	}
}

// Любой отказ должен давать пробе настоящий сайт: считаем зонды, пришедшие на «сайт», и сверяем ответ.
func TestProbesSeeRealSite(t *testing.T) {
	addr, hits, stop := decoy(t)
	defer stop()
	cc, sc, _ := configs(t)
	fb := &Fallback{Dest: func(string) string { return addr }, IdleTimeout: 3 * time.Second}

	listen := func() (net.Listener, string) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { Accept(c, sc, fb); c.Close() }()
			}
		}()
		return l, l.Addr().String()
	}
	l, front := listen()
	defer l.Close()

	// 1. обычный браузер (Go TLS-клиент) приходит на наш порт: должен получить страницу сайта
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
	resp, err := hc.Get("https://" + front + "/")
	if err != nil {
		t.Fatal("browser-like probe:", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "real decoy site" {
		t.Fatalf("probe got %q", body)
	}

	// 2. ClientHello нашего клиента, но с чужим ключом / неразрешённый / устаревший: тоже настоящий сайт
	cases := map[string]func(*Config){
		"wrong server key": func(c *Config) { c.ServerPub = newKey(t).Public },
		"stale":            func(c *Config) { c.Now = func() time.Time { return time.Now().Add(-time.Hour) } },
		"unknown client":   func(c *Config) { c.Static = newKey(t) },
	}
	for name, mut := range cases {
		c2 := *cc
		mut(&c2)
		raw, err := net.Dial("tcp", front)
		if err != nil {
			t.Fatal(err)
		}
		rec, _, err := buildHello(&c2, "www.yandex.ru")
		if err != nil {
			t.Fatal(err)
		}
		before := hits.Load()
		raw.Write(rec)
		// с настоящего сайта в ответ должен прийти ServerHello (TLS 1.3, запись 0x16)
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		var h [5]byte
		if _, err := io.ReadFull(raw, h[:]); err != nil || h[0] != recHandshake {
			t.Fatalf("%s: no ServerHello from real site (%v, %x)", name, err, h)
		}
		raw.Close()
		if hits.Load() != before+1 {
			t.Fatalf("%s: probe did not reach the real site (hits %d -> %d)", name, before, hits.Load())
		}
	}

	// 3. мусор вместо TLS: настоящий сайт закрывает соединение, как и положено; мы не отвечаем ничем своим
	raw, _ := net.Dial("tcp", front)
	raw.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	n, _ := raw.Read(buf)
	if bytes.Contains(buf[:n], []byte("ct2")) {
		t.Fatal("our protocol leaked into probe response")
	}
	raw.Close()
}

// Hello должен разбираться стандартным TLS-сервером (Go crypto/tls): значит, формат валиден, а наши правки не ломают структуру.
func TestHelloParsesWithStdTLS(t *testing.T) {
	cc, _, _ := configs(t)
	rec, _, err := buildHello(cc, "www.yandex.ru")
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	got := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		s := tls.Server(b, &tls.Config{GetConfigForClient: func(ci *tls.ClientHelloInfo) (*tls.Config, error) {
			got <- ci
			return nil, errors.New("stop")
		}})
		s.Handshake()
		b.Close()
	}()
	a.Write(rec)
	select {
	case ci := <-got:
		if ci.ServerName != "www.yandex.ru" || len(ci.CipherSuites) < 5 || len(ci.SupportedVersions) == 0 {
			t.Fatalf("unexpected hello: %+v", ci)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("std TLS server did not parse the hello")
	}
	a.Close()
}

// Отпечаток: набор расширений и число шифров не отличаются между соединениями (Chrome перемешивает порядок, но не набор);
// длина ClientHello не постоянна (длина GREASE-ECH у Chrome разная), а наша вставка её не меняет.
func TestHelloKeepsChromeShape(t *testing.T) {
	cc, _, _ := configs(t)
	isGrease := func(v int) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }
	var wantSet map[int]bool
	lens := map[int]int{}
	for i := 0; i < 60; i++ {
		rec, _, err := buildHello(cc, "www.yandex.ru")
		if err != nil {
			t.Fatal(err)
		}
		raw := rec[5:]
		lens[len(raw)]++
		p := 4 + 2 + 32 + 1 + int(raw[4+2+32])
		cs := int(raw[p])<<8 | int(raw[p+1])
		p += 2 + cs
		p += 1 + int(raw[p])
		el := int(raw[p])<<8 | int(raw[p+1])
		p += 2
		set := map[int]bool{}
		for e := raw[p : p+el]; len(e) >= 4; {
			ty, l := int(e[0])<<8|int(e[1]), int(e[2])<<8|int(e[3])
			if !isGrease(ty) {
				set[ty] = true
			}
			e = e[4+l:]
		}
		if wantSet == nil {
			wantSet = set
			for _, need := range []int{extSNI, extKeyShare, extECH, 0x0010, 0x002b, 0x000d} {
				if !set[need] {
					t.Fatalf("extension %#x missing", need)
				}
			}
		} else if len(set) != len(wantSet) {
			t.Fatalf("extension set differs between hellos: %v vs %v", set, wantSet)
		} else {
			for k := range wantSet {
				if !set[k] {
					t.Fatalf("extension %#x missing in some hello", k)
				}
			}
		}
	}
	if len(lens) < 2 {
		t.Fatalf("hello length constant %v: should vary like real Chrome (ECH padding)", lens)
	}
}

// Статистика: части рукопожатия в ClientHello (ECH-блок, ключ в key_share кроме старшего бита) не должны иметь постоянных битов.
func TestHelloBlobBitsUniform(t *testing.T) {
	const N = 2000
	cc, _, _ := configs(t)
	var echOnes [echBlobLen * 8]int
	var sidOnes [32 * 8]int
	var ksOnes [32 * 8]int
	for i := 0; i < N; i++ {
		rec, _, err := buildHello(cc, "www.yandex.ru")
		if err != nil {
			t.Fatal(err)
		}
		h, _ := parseHello(rec[5:])
		for b := 0; b < echBlobLen*8; b++ {
			if h.echPayload[b/8]>>(b%8)&1 == 1 {
				echOnes[b]++
			}
		}
		for b := 0; b < 256; b++ {
			if h.sid[b/8]>>(b%8)&1 == 1 {
				sidOnes[b]++
			}
			if h.keyShare[b/8]>>(b%8)&1 == 1 {
				ksOnes[b]++
			}
		}
	}
	sigma := math.Sqrt(0.25 / N)
	chk := func(name string, ones []int, skip map[int]bool) {
		for b, c := range ones {
			if skip[b] {
				continue
			}
			if p := float64(c) / N; math.Abs(p-0.5) > 6*sigma {
				t.Fatalf("%s bit %d frequency %.3f", name, b, p)
			}
		}
	}
	chk("ech", echOnes[:], nil)
	chk("session_id", sidOnes[:], nil)
	// У настоящих ключей X25519 старший бит последнего байта всегда 0 (это норма и для Chrome); остальные биты — монетка
	chk("key_share", ksOnes[:], map[int]bool{255: true})
	if ksOnes[255] != 0 {
		t.Fatalf("key_share top bit should be 0 like real X25519 keys, got %d", ksOnes[255])
	}
}

func TestCarrierReplayFallsBack(t *testing.T) {
	addr, _, stop := decoy(t)
	defer stop()
	cc, sc, _ := configs(t)
	fb := &Fallback{Dest: func(string) string { return addr }, IdleTimeout: 2 * time.Second}
	rec, _, err := buildHello(cc, "www.yandex.ru")
	if err != nil {
		t.Fatal(err)
	}
	use := func() error {
		a, b := net.Pipe()
		go func() { a.Write(rec); io.Copy(io.Discard, a) }()
		defer b.Close()
		_, err := Accept(b, sc, fb)
		return err
	}
	// первый раз: рукопожатие проходит, затем клиент молчит (соединение уходит как «свой»)
	a, b := net.Pipe()
	go func() { a.Write(rec); io.Copy(io.Discard, a) }()
	if _, err := Accept(b, sc, fb); err != nil {
		t.Fatal("first use:", err)
	}
	b.Close()
	if err := use(); !errors.Is(err, ErrFallback) {
		t.Fatal("replayed hello must go to fallback, got", err)
	}
}

func FuzzParseHello(f *testing.F) {
	cc, _, _ := configs(f)
	rec, _, _ := buildHello(cc, "www.yandex.ru")
	f.Add(rec[5:])
	f.Add([]byte{1, 0, 0, 5, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		if h, err := parseHello(data); err == nil && h.usable() {
			_ = h.keyShare[31] + h.echPayload[echBlobLen-1]
		}
	})
}

// memConn — соединение в памяти: читает заданные байты и отдаёт EOF, запись выбрасывает. Не блокируется, поэтому подходит для фаззинга.
type memConn struct {
	r *bytes.Reader
}

func (m *memConn) Read(p []byte) (int, error)       { return m.r.Read(p) }
func (m *memConn) Write(p []byte) (int, error)      { return len(p), nil }
func (m *memConn) Close() error                     { return nil }
func (m *memConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m *memConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m *memConn) SetDeadline(time.Time) error      { return nil }
func (m *memConn) SetReadDeadline(time.Time) error  { return nil }
func (m *memConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzAccept(f *testing.F) {
	cc, _, _ := configs(f)
	rec, _, _ := buildHello(cc, "www.yandex.ru")
	f.Add(rec)
	f.Add(append([]byte{0x16, 3, 1, 0, 60}, make([]byte, 60)...))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	sk := newKey(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		sc := &Config{Static: sk, Allowed: func([]byte) bool { return true }}
		sc.SetReplayCache(NewReplayCache())
		Accept(&memConn{r: bytes.NewReader(data)}, sc, &Fallback{}) // без резервного адреса: не должно паниковать и зависать
	})
}

// Сетевой тест (CT2_NET=1): наш сервер стоит перед настоящим сайтом; браузерный клиент должен увидеть настоящий сертификат и страницу.
func TestRealSiteFallbackNetwork(t *testing.T) {
	if os.Getenv("CT2_NET") == "" {
		t.Skip("CT2_NET не задан")
	}
	_, sc, _ := configs(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fb := &Fallback{Dest: func(sni string) string { return net.JoinHostPort("www.yandex.ru", "443") }, IdleTimeout: 10 * time.Second}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { Accept(c, sc, fb); c.Close() }()
		}
	}()
	var cert string
	hc := &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:     func(ctx context.Context, n, a string) (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) },
			TLSClientConfig: &tls.Config{ServerName: "www.yandex.ru"},
		}}
	resp, err := hc.Get("https://www.yandex.ru/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert = resp.TLS.PeerCertificates[0].Subject.CommonName
	}
	t.Logf("status %d, certificate verified by system roots, CN=%q", resp.StatusCode, cert)
	if resp.StatusCode < 200 || resp.StatusCode > 399 {
		t.Fatal("unexpected status", resp.StatusCode)
	}
}

// BenchmarkAccept меряет цену одного рукопожатия на сервере (две операции X25519 и разбор ClientHello): это граница для лимитов.
func BenchmarkAccept(b *testing.B) {
	cc, sc, _ := configs(b)
	rec, _, err := buildHello(cc, "www.yandex.ru")
	if err != nil {
		b.Fatal(err)
	}
	sc.SetReplayCache(nil)
	m1 := rec[5:]
	h, _ := parseHello(m1)
	msg := append(append([]byte{}, h.keyShare...), h.echPayload[:echBlobLen]...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.respond(prologueTLS(h.random), msg)
	}
}

// BenchmarkTCPLoopback: скорость через настоящий TCP на localhost (рукопожатие TLS-слоя и 16-килобайтные записи).
func BenchmarkTCPLoopback(b *testing.B) {
	cc, sc, _ := configs(b)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	srvc := make(chan *Conn, 1)
	go func() {
		c, _ := l.Accept()
		cn, err := Accept(c, sc, &Fallback{})
		if err != nil {
			b.Error(err)
		}
		srvc <- cn
	}()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	cli, err := DialTLS(raw, cc, "www.yandex.ru")
	if err != nil {
		b.Fatal(err)
	}
	srv := <-srvc
	go io.Copy(io.Discard, srv)
	msg := make([]byte, 1<<20)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cli.Write(msg)
	}
}
