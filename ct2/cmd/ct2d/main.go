// ct2d — сервер Coral Transport v2. Принимает соединения ct2 (TLS-подобное рукопожатие), чужих передаёт настоящему сайту,
// своих соединяет с upstream (например, локальный Shadowsocks/sing-box). Список пользователей перечитывается при изменении файла.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"coral/ct2"
)

func main() {
	listen := flag.String("listen", ":9600", "адрес для приёма")
	keyHex := flag.String("key", "", "приватный ключ сервера (hex) или переменная CT2_KEY")
	usersPath := flag.String("users", "users.json", "файл со списком публичных ключей пользователей (запасной источник)")
	usersURL := flag.String("users-url", "", "адрес панели со списком ключей (https://…/api/ct2/users): узел сам забирает список, ручное копирование не нужно")
	usersToken := flag.String("users-token", "", "токен для панели или переменная CT2_SYNC_TOKEN")
	usersEvery := flag.Duration("users-interval", 30*time.Second, "как часто опрашивать панель")
	usersCache := flag.String("users-cache", "", "файл кэша последнего хорошего списка (по умолчанию /var/lib/ct2/users.cache.json при -users-url)")
	upstream := flag.String("upstream", "127.0.0.1:18388", "куда передавать расшифрованный трафик")
	fallback := flag.String("fallback", "www.yandex.ru:443", "резервный сайт для чужих соединений")
	sniList := flag.String("sni", "www.yandex.ru,ya.ru,dl.google.com,www.cloudflare.com", "имена, для которых проба идёт на сайт с тем же именем")
	rate := flag.Float64("rate", 50, "рукопожатий в секунду с одного адреса (за мобильным NAT сидят тысячи людей)")
	burst := flag.Float64("burst", 200, "всплеск рукопожатий с одного адреса")
	maxHS := flag.Int("max-handshakes", 64, "одновременных рукопожатий")
	maxFB := flag.Int("max-fallback", 256, "одновременных резервных соединений")
	flag.Parse()
	if *keyHex == "" {
		*keyHex = os.Getenv("CT2_KEY")
	}
	priv, err := hex.DecodeString(strings.TrimSpace(*keyHex))
	if err != nil || len(priv) != 32 {
		log.Fatal("нужен приватный ключ сервера (32 байта hex): -key или CT2_KEY")
	}
	kp, err := ct2.KeyFromPrivate(priv)
	if err != nil {
		log.Fatal(err)
	}
	us := &ct2.UserList{}
	if _, err := os.Stat(*usersPath); err == nil {
		us.LoadFile(*usersPath)
		go func() {
			for range time.Tick(10 * time.Second) {
				us.LoadFile(*usersPath)
			}
		}()
	}
	if *usersURL != "" {
		tok := *usersToken
		if tok == "" {
			tok = os.Getenv("CT2_SYNC_TOKEN")
		}
		if tok == "" {
			log.Fatal("для -users-url нужен токен: -users-token или CT2_SYNC_TOKEN")
		}
		cache := *usersCache
		if cache == "" {
			cache = "/var/lib/ct2/users.cache.json"
		}
		go us.Run(context.Background(), ct2.SyncConfig{URL: *usersURL, Token: tok, Interval: *usersEvery, CachePath: cache})
	}

	var reg ct2.Registry
	go func() { // раз в 3 с закрываем сеансы пользователей, которых больше нет в списке (отзыв, истёкшая подписка)
		for range time.Tick(3 * time.Second) {
			if n := reg.Sweep(us.Allowed); n > 0 {
				log.Printf("users: закрыто сеансов отозванных ключей: %d", n)
			}
		}
	}()
	cfg := &ct2.Config{Static: kp, Allowed: us.Allowed, Limiter: ct2.NewLimiter(*rate, *burst, *maxHS)}
	cfg.SetReplayCache(ct2.NewReplayCache())
	allowSNI := map[string]bool{}
	for _, n := range strings.Split(*sniList, ",") {
		allowSNI[strings.TrimSpace(n)] = true
	}
	fb := &ct2.Fallback{MaxConns: *maxFB, Dest: func(sni string) string {
		if allowSNI[sni] {
			return net.JoinHostPort(sni, "443")
		}
		return *fallback
	}}

	var ok, other, active atomic.Int64
	go func() {
		for range time.Tick(time.Minute) {
			log.Printf("статистика за минуту: свои=%d прочие/резерв=%d активных=%d", ok.Swap(0), other.Swap(0), active.Load())
		}
	}()
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ct2d слушает %s, upstream %s, резервный сайт %s, публичный ключ %s", *listen, *upstream, *fallback, hex.EncodeToString(kp.Public))
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			cn, err := ct2.Accept(c, cfg, fb)
			if err != nil {
				other.Add(1)
				return
			}
			ok.Add(1)
			active.Add(1)
			defer active.Add(-1)
			defer reg.Add(cn)()
			ct2.ServeMux(cn, func(st net.Conn) {
				defer st.Close()
				up, err := net.DialTimeout("tcp", *upstream, 5*time.Second)
				if err != nil {
					return
				}
				pipe(st, up)
			})
		}()
	}
}

func pipe(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.Close()
		src.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
