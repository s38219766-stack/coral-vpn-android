package ct2

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestLimiterTokenBucket(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(1, 3, 100)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if rel, ok := l.Allow("1.1.1.1"); !ok {
			t.Fatalf("burst %d denied", i)
		} else {
			rel()
		}
	}
	if _, ok := l.Allow("1.1.1.1"); ok {
		t.Fatal("4th must be denied")
	}
	if rel, ok := l.Allow("2.2.2.2"); !ok {
		t.Fatal("other IP must not be affected")
	} else {
		rel()
	}
	now = now.Add(1100 * time.Millisecond)
	if rel, ok := l.Allow("1.1.1.1"); !ok {
		t.Fatal("token must refill after 1s")
	} else {
		rel()
	}
}

func TestLimiterConcurrencyCap(t *testing.T) {
	l := NewLimiter(1000, 1000, 2)
	r1, ok1 := l.Allow("a")
	r2, ok2 := l.Allow("b")
	if !ok1 || !ok2 {
		t.Fatal("first two must pass")
	}
	if _, ok := l.Allow("c"); ok {
		t.Fatal("third concurrent must be denied")
	}
	r1()
	if rel, ok := l.Allow("c"); !ok {
		t.Fatal("must pass after release")
	} else {
		rel()
	}
	r2()
}

func TestLimiterMemoryBounded(t *testing.T) {
	l := NewLimiter(1, 1, 1<<20)
	l.MaxIPs = 1000
	for i := 0; i < 200000; i++ {
		if rel, ok := l.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)); ok {
			rel()
		}
	}
	if len(l.perIP) > 1000 {
		t.Fatalf("limiter map grew to %d", len(l.perIP))
	}
}

type addrConn struct {
	*memConn
	ip string
}

func (a *addrConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP(a.ip), Port: 1234} }

// Флуд с одного адреса: после всплеска настоящие рукопожатия идут на резервный сайт; другие адреса не страдают.
func TestAcceptRateLimited(t *testing.T) {
	cc, sc, _ := configs(t)
	sc.Limiter = NewLimiter(0.001, 3, 100)
	run := func(ip string) error {
		rec, _, err := buildHello(cc, "www.yandex.ru")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Accept(&addrConn{&memConn{r: bytes.NewReader(rec)}, ip}, sc, &Fallback{})
		return err
	}
	ok, denied := 0, 0
	for i := 0; i < 10; i++ {
		if err := run("9.9.9.9"); err == nil {
			ok++
		} else if errors.Is(err, ErrFallback) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 3 || denied != 7 {
		t.Fatalf("from one IP: ok=%d denied=%d, want 3/7", ok, denied)
	}
	for i := 0; i < 10; i++ {
		if err := run(fmt.Sprintf("8.8.8.%d", i)); err != nil {
			t.Fatalf("different IP %d affected: %v", i, err)
		}
	}
}

// Неудачные рукопожатия (сканер) быстро упираются в лимит, а настоящий пользователь с тем же всплеском остаётся в норме.
func TestFailPenalty(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewLimiter(1, 20, 100)
	l.now = func() time.Time { return now }
	passed := 0
	for i := 0; i < 20; i++ {
		rel, ok := l.Allow("6.6.6.6")
		if !ok {
			break
		}
		rel()
		passed++
		l.Fail("6.6.6.6")
	}
	if passed > 6 {
		t.Fatalf("scanner with only failures passed %d times, penalty not effective", passed)
	}
	good := 0
	for i := 0; i < 20; i++ {
		rel, ok := l.Allow("7.7.7.7")
		if !ok {
			break
		}
		rel()
		good++
	}
	if good != 20 {
		t.Fatalf("legitimate client limited to %d of 20", good)
	}
}
