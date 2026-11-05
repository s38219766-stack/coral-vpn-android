package ct2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// UserList — список разрешённых публичных ключей пользователей. Источники: файл (перечитывается при изменении) и адрес на панели
// (опрос с ETag). Новый список заменяет прежний целиком, поэтому отзыв ключа и истёкшая подписка действуют сразу после ближайшего опроса.
// Защита от поломки на стороне панели: пустой список не принимается (иначе ошибка панели отключила бы всех).
type UserList struct {
	set  atomic.Pointer[map[string]string]
	mu   sync.Mutex
	etag string
	mod  time.Time
	// Logf принимает сообщения о смене списка и ошибках (по умолчанию log.Printf).
	Logf func(format string, args ...any)
}

type userEntry struct {
	Name string `json:"name"`
	Pub  string `json:"pub"`
}

var (
	ErrEmptyList = errors.New("ct2: empty user list rejected")
	ErrBadList   = errors.New("ct2: bad user list")
)

func (u *UserList) logf(f string, a ...any) {
	if u.Logf != nil {
		u.Logf(f, a...)
		return
	}
	log.Printf(f, a...)
}

// Allowed подходит как Config.Allowed.
func (u *UserList) Allowed(pub []byte) bool {
	m := u.set.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[string(pub)]
	return ok
}

// Len — число ключей в текущем списке.
func (u *UserList) Len() int {
	if m := u.set.Load(); m != nil {
		return len(*m)
	}
	return 0
}

// Replace разбирает JSON `[{"name":"…","pub":"hex32"}]` и подменяет список. При ошибке прежний список остаётся.
func (u *UserList) Replace(b []byte) error {
	var es []userEntry
	if err := json.Unmarshal(b, &es); err != nil {
		return fmt.Errorf("%w: %v", ErrBadList, err)
	}
	m := make(map[string]string, len(es))
	for _, e := range es {
		if p, err := hex.DecodeString(e.Pub); err == nil && len(p) == 32 {
			m[string(p)] = e.Name
		}
	}
	if len(m) == 0 && u.Len() > 0 {
		return ErrEmptyList
	}
	if len(m) == 0 && len(es) > 0 {
		return ErrBadList
	}
	u.set.Store(&m)
	return nil
}

// LoadFile перечитывает файл, если он изменился с прошлого раза.
func (u *UserList) LoadFile(path string) {
	st, err := os.Stat(path)
	if err != nil {
		u.logf("users: %v", err)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if st.ModTime().Equal(u.mod) {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		u.logf("users: %v", err)
		return
	}
	if err := u.Replace(b); err != nil {
		u.logf("users: файл %s: %v (прежний список сохранён)", path, err)
		return
	}
	u.mod = st.ModTime()
	u.logf("users: из файла загружено %d", u.Len())
}

// Fetch забирает список с адреса (Bearer-токен, ETag). Возвращает, изменился ли список.
func (u *UserList) Fetch(ctx context.Context, hc *http.Client, url, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	u.mu.Lock()
	et := u.etag
	u.mu.Unlock()
	if et != "" {
		req.Header.Set("If-None-Match", et)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return false, nil
	case resp.StatusCode != http.StatusOK:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return false, fmt.Errorf("панель ответила %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return false, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.Replace(b); err != nil {
		return false, err
	}
	u.etag = resp.Header.Get("ETag")
	return true, nil
}

// SyncConfig — настройки опроса панели.
type SyncConfig struct {
	URL      string
	Token    string
	Interval time.Duration // по умолчанию 30 с
	// CachePath — куда сохранять последний хороший список: после перезапуска узел работает, даже если панель недоступна.
	CachePath string
	Client    *http.Client
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Run загружает кэш (если список пуст) и опрашивает панель, пока не отменён ctx. Ошибки не рвут работу: остаётся последний хороший список.
func (u *UserList) Run(ctx context.Context, c SyncConfig) {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	hc := c.Client
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	if c.CachePath != "" && u.Len() == 0 {
		if b, err := os.ReadFile(c.CachePath); err == nil {
			if err := u.Replace(b); err == nil {
				u.logf("users: из кэша загружено %d", u.Len())
			}
		}
	}
	failed := 0
	tick := func() {
		changed, err := u.Fetch(ctx, hc, c.URL, c.Token)
		if err != nil {
			failed++
			if failed == 1 || failed%20 == 0 { // не засоряем журнал: первая ошибка и затем раз в ~10 минут
				u.logf("users: синхронизация с панелью: %v (работаем на прежнем списке, ключей %d)", err, u.Len())
			}
			return
		}
		failed = 0
		if changed {
			u.logf("users: с панели получено %d ключей", u.Len())
			if c.CachePath != "" {
				if m := u.set.Load(); m != nil {
					out := make([]userEntry, 0, len(*m))
					for k, n := range *m {
						out = append(out, userEntry{Name: n, Pub: hex.EncodeToString([]byte(k))})
					}
					if b, err := json.Marshal(out); err == nil {
						if err := writeAtomic(c.CachePath, b); err != nil {
							u.logf("users: кэш не сохранён: %v", err)
						}
					}
				}
			}
		}
	}
	tick()
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
		}
	}
}
