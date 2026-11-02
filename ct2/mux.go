package ct2

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// Мультиплексирование: один сеанс ct2 несёт много потоков (smux). Рукопожатие идёт один раз на сеанс, а новый поток открывается
// без ожидания ответа. Это убирает лишний круговой обход на каждое TCP-соединение приложения.

func muxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = 10 * time.Second
	c.KeepAliveTimeout = 30 * time.Second
	c.MaxReceiveBuffer = 4 << 20
	c.MaxStreamBuffer = 1 << 20
	return c
}

// ServeMux принимает потоки сеанса и вызывает handle для каждого в своей горутине; возвращается, когда сеанс закрыт.
func ServeMux(c *Conn, handle func(net.Conn)) error {
	s, err := smux.Server(c, muxConfig())
	if err != nil {
		return err
	}
	defer s.Close()
	for {
		st, err := s.AcceptStream()
		if err != nil {
			return err
		}
		// smux (v1.5.34, issue #997) вешает на принятый поток финализатор, который закрывает поток, как только обёртка перестаёт
		// быть достижимой: при io.Copy это случается после первой сборки мусора, и поток обрывается посреди передачи.
		runtime.SetFinalizer(st, nil)
		go func() {
			defer runtime.KeepAlive(st)
			handle(st)
		}()
	}
}

// Pool держит несколько сеансов с сервером и раздаёт потоки по наименее загруженному. Сеанс, который умер, заменяется новым.
type Pool struct {
	Dial func() (*Conn, error) // создаёт новый сеанс (рукопожатие)
	Size int                   // максимум сеансов (по умолчанию 2)
	// Spread — при скольких потоках на самом свободном сеансе открывается ещё один (по умолчанию 16)
	Spread int

	mu       sync.Mutex
	sessions []*smux.Session
}

func (p *Pool) prune() {
	live := p.sessions[:0]
	for _, s := range p.sessions {
		if !s.IsClosed() {
			live = append(live, s)
		}
	}
	p.sessions = live
}

func (p *Pool) pick() (*smux.Session, error) {
	size, spread := p.Size, p.Spread
	if size <= 0 {
		size = 2
	}
	if spread <= 0 {
		spread = 16
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune()
	var best *smux.Session
	for _, s := range p.sessions {
		if best == nil || s.NumStreams() < best.NumStreams() {
			best = s
		}
	}
	if best != nil && (len(p.sessions) >= size || best.NumStreams() < spread) {
		return best, nil
	}
	cn, err := p.Dial()
	if err != nil {
		if best != nil {
			return best, nil // новый сеанс не вышел, работаем на имеющемся
		}
		return nil, err
	}
	s, err := smux.Client(cn, muxConfig())
	if err != nil {
		cn.Close()
		return nil, err
	}
	p.sessions = append(p.sessions, s)
	return s, nil
}

// Open открывает новый поток; при мёртвом сеансе один раз пробует заново на другом.
func (p *Pool) Open() (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := p.pick()
		if err != nil {
			return nil, err
		}
		st, err := s.OpenStream()
		if err == nil {
			return st, nil
		}
		s.Close()
	}
	return nil, errors.New("ct2: cannot open stream")
}

// Close закрывает все сеансы.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		s.Close()
	}
	p.sessions = nil
}

// Sessions возвращает число живых сеансов (для тестов и статистики).
func (p *Pool) Sessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune()
	return len(p.sessions)
}
