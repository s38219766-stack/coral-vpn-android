// ct2c — клиент Coral Transport v2: слушает локальный порт и пересылает соединения на сервер ct2d.
package main

import (
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"coral/ct2"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:1081", "локальный адрес")
	server := flag.String("server", "", "адрес сервера host:port")
	serverPub := flag.String("server-pub", "", "публичный ключ сервера (hex)")
	keyHex := flag.String("key", "", "приватный ключ пользователя (hex) или CT2_USER_KEY")
	sni := flag.String("sni", "www.yandex.ru", "имя сайта для маскировки")
	sessions := flag.Int("sessions", 2, "сколько сеансов ct2 держать одновременно (потоки распределяются между ними)")
	flag.Parse()
	if *keyHex == "" {
		*keyHex = os.Getenv("CT2_USER_KEY")
	}
	priv, err1 := hex.DecodeString(strings.TrimSpace(*keyHex))
	spub, err2 := hex.DecodeString(strings.TrimSpace(*serverPub))
	if err1 != nil || err2 != nil || len(priv) != 32 || len(spub) != 32 || *server == "" {
		log.Fatal("нужны -server, -server-pub (32 байта hex) и -key или CT2_USER_KEY (32 байта hex)")
	}
	kp, err := ct2.KeyFromPrivate(priv)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &ct2.Config{Static: kp, ServerPub: spub}
	pool := &ct2.Pool{Size: *sessions, Dial: func() (*ct2.Conn, error) {
		host, _, _ := net.SplitHostPort(*server)
		rc, err := net.DialTimeout("tcp", *server, 8*time.Second)
		if err != nil {
			log.Printf("host fail %s", host) // приложение превращает такие строки в анонимную статистику по адресам
			return nil, err
		}
		cn, err := ct2.DialTLS(rc, cfg, *sni)
		if err != nil {
			rc.Close()
			log.Printf("рукопожатие: %v", err)
			log.Printf("host fail %s", host)
			return nil, err
		}
		log.Printf("host ok %s", host)
		return cn, nil
	}}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ct2c слушает %s -> %s (маска %s, сеансов до %d)", *listen, *server, *sni, *sessions)
	for {
		lc, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer lc.Close()
			st, err := pool.Open()
			if err != nil {
				log.Printf("поток: %v", err)
				return
			}
			var wg sync.WaitGroup
			wg.Add(2)
			cp := func(dst io.WriteCloser, src io.ReadCloser) {
				defer wg.Done()
				io.Copy(dst, src)
				dst.Close()
				src.Close()
			}
			go cp(st, lc)
			go cp(lc, st)
			wg.Wait()
		}()
	}
}
