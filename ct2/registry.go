package ct2

import "sync"

// Registry помнит открытые сеансы, чтобы после отзыва ключа (пользователь исчез из списка или подписка истекла) закрыть уже идущие
// сеансы: иначе отзыв действовал бы только на новые подключения, а долгий сеанс жил бы сколько угодно.
type Registry struct {
	mu sync.Mutex
	m  map[*Conn]struct{}
}

// Add регистрирует сеанс; вызовите возвращённую функцию, когда сеанс закончился.
func (r *Registry) Add(c *Conn) (remove func()) {
	r.mu.Lock()
	if r.m == nil {
		r.m = map[*Conn]struct{}{}
	}
	r.m[c] = struct{}{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.m, c)
		r.mu.Unlock()
	}
}

// Len — число открытых сеансов.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// Sweep закрывает сеансы, чей ключ больше не разрешён; возвращает, сколько закрыто.
func (r *Registry) Sweep(allowed func(pub []byte) bool) int {
	r.mu.Lock()
	var kill []*Conn
	for c := range r.m {
		if !allowed(c.PeerStatic()) {
			kill = append(kill, c)
		}
	}
	r.mu.Unlock()
	for _, c := range kill {
		c.Close()
	}
	return len(kill)
}
