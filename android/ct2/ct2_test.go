package ct2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

func newKey(t testing.TB) noise.DHKey {
	k, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pair поднимает рукопожатие через net.Pipe и возвращает обе стороны.
func pair(t testing.TB, cc, sc *Config) (cli, srv *Conn, cerr, serr error) {
	a, b := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv, serr = Server(b, sc)
		if serr != nil {
			b.Close()
		}
	}()
	cli, cerr = Client(a, cc)
	if cerr != nil {
		a.Close()
	}
	wg.Wait()
	return
}

func configs(t testing.TB) (cc, sc *Config, cpub noise.DHKey) {
	ck, sk := newKey(t), newKey(t)
	cc = &Config{Static: ck, ServerPub: sk.Public}
	sc = &Config{Static: sk, Allowed: func(p []byte) bool { return bytes.Equal(p, ck.Public) }}
	sc.SetReplayCache(NewReplayCache())
	return cc, sc, ck
}

func TestRoundTrip(t *testing.T) {
	cc, sc, ck := configs(t)
	cli, srv, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	if !bytes.Equal(srv.PeerStatic(), ck.Public) || !bytes.Equal(cli.PeerStatic(), sc.Static.Public) {
		t.Fatal("peer static mismatch")
	}
	for _, n := range []int{0, 1, 15, 16, 1399, 16000, 16001, 100000} {
		msg := make([]byte, n)
		rand.Read(msg)
		go func() { cli.Write(msg) }()
		got := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(srv, got); err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("n=%d: data mismatch", n)
		}
		go func() { srv.Write(msg) }()
		if n > 0 {
			if _, err := io.ReadFull(cli, got); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("reverse n=%d: %v", n, err)
			}
		}
	}
}

func TestWrongServerKey(t *testing.T) {
	cc, sc, _ := configs(t)
	cc.ServerPub = newKey(t).Public
	_, _, ce, se := pair(t, cc, sc)
	if se == nil || ce == nil {
		t.Fatal("handshake with wrong server key must fail on both sides", ce, se)
	}
}

func TestUnauthorizedClient(t *testing.T) {
	cc, sc, _ := configs(t)
	sc.Allowed = func([]byte) bool { return false }
	_, _, _, se := pair(t, cc, sc)
	if !errors.Is(se, ErrUnauthorized) {
		t.Fatal("want ErrUnauthorized, got", se)
	}
}

// capture записывает всё, что пишет клиент, и не отвечает: нужно, чтобы получить «первый пакет» отдельно.
type capture struct{ w bytes.Buffer }

func (c *capture) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *capture) Read([]byte) (int, error)    { return 0, io.EOF }

func firstFlight(t testing.TB, cc *Config) []byte {
	c := &capture{}
	Client(c, cc)
	return append([]byte{}, c.w.Bytes()...)
}

func TestReplayedHandshakeRejected(t *testing.T) {
	cc, sc, _ := configs(t)
	flight := firstFlight(t, cc)
	if _, err := Server(&rwBuf{r: bytes.NewReader(flight)}, sc); err != nil {
		t.Fatal("first use must succeed:", err)
	}
	_, err := Server(&rwBuf{r: bytes.NewReader(flight)}, sc)
	if !errors.Is(err, ErrReplay) {
		t.Fatal("replay must be rejected, got", err)
	}
}

type rwBuf struct {
	r io.Reader
	w bytes.Buffer
}

func (b *rwBuf) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *rwBuf) Write(p []byte) (int, error) { return b.w.Write(p) }

func TestStaleTimestamp(t *testing.T) {
	cc, sc, _ := configs(t)
	cc.Now = func() time.Time { return time.Now().Add(-ClockSkew - 30*time.Second) }
	_, err := Server(&rwBuf{r: bytes.NewReader(firstFlight(t, cc))}, sc)
	if !errors.Is(err, ErrStale) {
		t.Fatal("want ErrStale, got", err)
	}
	cc.Now = func() time.Time { return time.Now().Add(ClockSkew + 30*time.Second) }
	_, err = Server(&rwBuf{r: bytes.NewReader(firstFlight(t, cc))}, sc)
	if !errors.Is(err, ErrStale) {
		t.Fatal("future timestamp: want ErrStale, got", err)
	}
}

// Любое изменение любого бита первого пакета должно ломать рукопожатие.
func TestTamperHandshake(t *testing.T) {
	cc, sc, _ := configs(t)
	flight := firstFlight(t, cc)
	for bit := 0; bit < (saltLen+msg1Len)*8; bit++ {
		f := append([]byte{}, flight...)
		f[bit/8] ^= 1 << (bit % 8)
		sc.SetReplayCache(NewReplayCache())
		if _, err := Server(&rwBuf{r: bytes.NewReader(f)}, sc); err == nil {
			t.Fatalf("bit %d flip accepted", bit)
		}
	}
}

func TestTamperTransport(t *testing.T) {
	probe := func(flip int) (n int, err error) {
		cc, sc, _ := configs(t)
		cc.Padder, sc.Padder = NoPadding{}, NoPadding{}
		cli, srv, ce, se := pair(t, cc, sc)
		if ce != nil || se != nil {
			t.Fatal(ce, se)
		}
		rec := &capture{}
		cli.rw = rec
		cli.Write([]byte("secret payload"))
		raw := append([]byte{}, rec.w.Bytes()...)
		if flip < 0 {
			return len(raw), nil
		}
		raw[flip/8] ^= 1 << (flip % 8)
		srv.rw = &rwBuf{r: bytes.NewReader(raw)}
		return srv.Read(make([]byte, 64))
	}
	size, _ := probe(-1)
	for bit := 0; bit < size*8; bit++ {
		if n, err := probe(bit); err == nil && n > 0 {
			t.Fatalf("bit %d flip accepted (%d bytes)", bit, n)
		}
	}
}

// Две сессии с теми же статическими ключами не должны давать ни одинаковых ключей, ни одинакового шифртекста (прямая секретность и соль).
func TestSessionsIndependent(t *testing.T) {
	cc, sc, _ := configs(t)
	cc.Padder, sc.Padder = NoPadding{}, NoPadding{}
	var recs [2][]byte
	for i := range recs {
		cli, _, ce, se := pair(t, cc, sc)
		if ce != nil || se != nil {
			t.Fatal(ce, se)
		}
		r := &capture{}
		cli.rw = r
		cli.Write([]byte("same plaintext"))
		recs[i] = r.w.Bytes()
		sc.SetReplayCache(NewReplayCache())
	}
	if bytes.Equal(recs[0], recs[1]) {
		t.Fatal("identical ciphertext in two sessions")
	}
}

func TestRekey(t *testing.T) {
	cc, sc, _ := configs(t)
	cc.RekeyFrames, sc.RekeyFrames = 4, 4
	cli, srv, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	go func() {
		for i := 0; i < 50; i++ {
			cli.Write(bytes.Repeat([]byte{byte(i)}, 100))
		}
	}()
	for i := 0; i < 50; i++ {
		got := make([]byte, 100)
		if _, err := io.ReadFull(srv, got); err != nil || got[0] != byte(i) {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
}

func TestPaddingBuckets(t *testing.T) {
	cc, sc, _ := configs(t)
	cli, _, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	sizes := map[int]int{}
	for _, n := range []int{1, 10, 50, 100, 120, 200, 400, 900, 1300} {
		r := &capture{}
		cli.rw = r
		cli.Write(make([]byte, n))
		sizes[n] = r.w.Len()
	}
	if sizes[1] != sizes[100] || sizes[100] != sizes[120] {
		t.Fatalf("1, 100 и 120 байт должны давать одинаковую длину записи: %v", sizes)
	}
	if sizes[1] == sizes[900] {
		t.Fatal("разные корзины должны различаться")
	}
}

// Отпечаток: каждый бит первых 128 байт первого пакета должен быть «монеткой». Постоянный бит — сигнатура для DPI.
func TestNoConstantBitsInFirstFlight(t *testing.T) {
	const N = 3000
	cc, _, _ := configs(t)
	var ones [128 * 8]int
	for i := 0; i < N; i++ {
		f := firstFlight(t, cc)
		for b := 0; b < len(ones); b++ {
			if f[b/8]>>(b%8)&1 == 1 {
				ones[b]++
			}
		}
	}
	sigma := math.Sqrt(0.25 / N)
	for b, c := range ones {
		if p := float64(c) / N; math.Abs(p-0.5) > 6*sigma {
			t.Fatalf("bit %d has frequency %.3f", b, p)
		}
	}
}

// Длина первого пакета не должна быть постоянной (иначе её можно использовать как сигнатуру).
func TestFirstFlightLengthVaries(t *testing.T) {
	cc, _, _ := configs(t)
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		seen[len(firstFlight(t, cc))] = true
	}
	if len(seen) < 50 {
		t.Fatal("too few distinct first-flight lengths:", len(seen))
	}
}

// ---------- известные ответы (для независимой проверки на Python) ----------

type detRand struct {
	n   uint64
	log []byte
}

func (d *detRand) Read(p []byte) (int, error) {
	for i := range p {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], d.n/32)
		h := sha256.Sum256(append([]byte("ct2-kat"), b[:]...))
		p[i] = h[d.n%32]
		d.n++
	}
	d.log = append(d.log, p...)
	return len(p), nil
}

type tee struct {
	r io.Reader
	w io.Writer
	t *bytes.Buffer
}

func (x *tee) Read(p []byte) (int, error)  { return x.r.Read(p) }
func (x *tee) Write(p []byte) (int, error) { x.t.Write(p); return x.w.Write(p) }

func TestKnownAnswerVector(t *testing.T) {
	out := os.Getenv("CT2_KAT_OUT")
	if out == "" {
		t.Skip("CT2_KAT_OUT не задан")
	}
	key := func(seed string) noise.DHKey {
		h := sha256.Sum256([]byte(seed))
		k, err := suite.GenerateKeypair(bytes.NewReader(h[:]))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	ss, cs := key("server-static"), key("client-static")
	now := time.Unix(1790000000, 0)
	cr, sr := &detRand{}, &detRand{n: 1 << 40}
	cc := &Config{Static: cs, ServerPub: ss.Public, Now: func() time.Time { return now }, Rand: cr, Padder: NoPadding{}}
	sc := &Config{Static: ss, Allowed: func([]byte) bool { return true }, Now: func() time.Time { return now }, Rand: sr, Padder: NoPadding{}}
	a, b := net.Pipe()
	var c2s, s2c bytes.Buffer
	var srv *Conn
	var serr error
	done := make(chan struct{})
	go func() { srv, serr = Server(&tee{r: b, w: b, t: &s2c}, sc); close(done) }()
	cli, err := Client(&tee{r: a, w: a, t: &c2s}, cc)
	<-done
	if err != nil || serr != nil {
		t.Fatal(err, serr)
	}
	hsC2S, hsS2C := append([]byte{}, c2s.Bytes()...), append([]byte{}, s2c.Bytes()...)
	c2s.Reset()
	s2c.Reset()
	go cli.Write([]byte("hello from client"))
	buf := make([]byte, 17)
	io.ReadFull(srv, buf)
	go srv.Write([]byte("hello from server"))
	io.ReadFull(cli, buf)
	v := map[string]string{
		"server_static_priv": hex.EncodeToString(ss.Private), "server_static_pub": hex.EncodeToString(ss.Public),
		"client_static_priv": hex.EncodeToString(cs.Private), "client_static_pub": hex.EncodeToString(cs.Public),
		"now": "1790000000", "client_rand": hex.EncodeToString(cr.log), "server_rand": hex.EncodeToString(sr.log),
		"hs_c2s": hex.EncodeToString(hsC2S), "hs_s2c": hex.EncodeToString(hsS2C),
		"rec_c2s": hex.EncodeToString(c2s.Bytes()), "rec_s2c": hex.EncodeToString(s2c.Bytes()),
	}
	j, _ := json.MarshalIndent(v, "", " ")
	os.WriteFile(out, j, 0o644)
}

// ---------- фаззинг ----------

func FuzzServerHandshake(f *testing.F) {
	cc, _, _ := configs(f)
	f.Add(firstFlight(f, cc))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 200))
	sk := newKey(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		sc := &Config{Static: sk, Allowed: func([]byte) bool { return true }}
		sc.SetReplayCache(NewReplayCache())
		Server(&rwBuf{r: bytes.NewReader(data)}, sc) // не должно паниковать и зависать
	})
}

func FuzzRecordReader(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 64))
	f.Add(bytes.Repeat([]byte{0xff}, 4096))
	f.Fuzz(func(t *testing.T, data []byte) {
		cc, sc, _ := configs(t)
		_, srv, ce, se := pair(t, cc, sc)
		if ce != nil || se != nil {
			t.Fatal(ce, se)
		}
		srv.rw = &rwBuf{r: bytes.NewReader(data)}
		buf := make([]byte, 128)
		for i := 0; i < 8; i++ {
			if _, err := srv.Read(buf); err != nil {
				break
			}
		}
	})
}

func BenchmarkThroughput(b *testing.B) {
	cc, sc, _ := configs(b)
	cli, srv, _, _ := pair(b, cc, sc)
	msg := make([]byte, 16000)
	b.SetBytes(int64(len(msg)))
	go func() {
		buf := make([]byte, len(msg))
		for {
			if _, err := io.ReadFull(srv, buf); err != nil {
				return
			}
		}
	}()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cli.Write(msg)
	}
}

func TestKeyFromPrivate(t *testing.T) {
	k := newKey(t)
	got, err := KeyFromPrivate(k.Private)
	if err != nil || !bytes.Equal(got.Public, k.Public) {
		t.Fatal("public key mismatch", err)
	}
	if _, err := KeyFromPrivate(k.Private[:31]); err == nil {
		t.Fatal("short key must fail")
	}
}
