package ct2

import (
	"net"
	"sync"
	"time"
)

// Limiter ограничивает число рукопожатий, пока они не дошли до дорогих операций (две X25519 на запрос, ~215 мкс).
// Лимит на адрес (корзина токенов) и общее число одновременных рукопожатий. Отказанное соединение уходит на резервный сайт,
// как любое другое чужое, поэтому по ответу флуд от настоящего пользователя не отличить.
type Limiter struct {
	Rate  float64 // рукопожатий в секунду с одного адреса
	Burst float64 // всплеск
	// FailPenalty — сколько токенов дополнительно списывается за неудачное рукопожатие: сканеры упираются в лимит быстрее настоящих
	// пользователей, чьи рукопожатия удаются.
	FailPenalty float64
	// MaxIPs — сколько адресов помним; при переполнении новые адреса делят общую корзину «прочих».
	MaxIPs int

	mu    sync.Mutex
	perIP map[string]*bucket
	other bucket
	sem   chan struct{}
	now   func() time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// NewLimiter создаёт ограничитель: rate/burst на адрес и не больше maxConcurrent рукопожатий одновременно.
func NewLimiter(rate, burst float64, maxConcurrent int) *Limiter {
	return &Limiter{Rate: rate, Burst: burst, FailPenalty: 4, MaxIPs: 100000, perIP: map[string]*bucket{}, sem: make(chan struct{}, maxConcurrent), now: time.Now}
}

func (b *bucket) take(l *Limiter, now time.Time) bool {
	if b.at.IsZero() {
		b.tokens, b.at = l.Burst, now
	}
	b.tokens += now.Sub(b.at).Seconds() * l.Rate
	if b.tokens > l.Burst {
		b.tokens = l.Burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Allow решает, пускать ли рукопожатие с адреса ip. release нужно вызвать после обработки.
func (l *Limiter) Allow(ip string) (release func(), ok bool) {
	now := l.now()
	l.mu.Lock()
	b := l.perIP[ip]
	if b == nil {
		if len(l.perIP) >= l.MaxIPs {
			for k, v := range l.perIP { // освобождаем давно неактивные адреса
				if now.Sub(v.at) > 10*time.Minute {
					delete(l.perIP, k)
				}
			}
		}
		if len(l.perIP) >= l.MaxIPs {
			b = &l.other
		} else {
			b = &bucket{}
			l.perIP[ip] = b
		}
	}
	pass := b.take(l, now)
	l.mu.Unlock()
	if !pass {
		return nil, false
	}
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, true
	default:
		return nil, false
	}
}

// Fail списывает штраф с адреса после неудачного рукопожатия.
func (l *Limiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.perIP[ip]; b != nil {
		b.tokens -= l.FailPenalty
		if b.tokens < -l.Burst {
			b.tokens = -l.Burst
		}
	}
}

func remoteIP(c net.Conn) string {
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}
