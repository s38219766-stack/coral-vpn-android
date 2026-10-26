package main

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

type Client struct {
	Remote string // сервер или несколько через запятую (мосты): при сбое берём следующий
	PortLo int
	PortHi int
	Key    []byte   // ключ пользователя
	SNI    []string // имена для маскировки (по умолчанию DefaultSNI); должны совпадать с серверными

	cur atomic.Int32 // индекс последнего рабочего сервера
}

func (cl *Client) hosts() []string {
	var out []string
	for _, h := range strings.Split(cl.Remote, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func (cl *Client) addrFor(host string, now time.Time) string {
	ke := epochKey(cl.Key, epochDay(now))
	return net.JoinHostPort(host, fmt.Sprint(portFor(ke, cl.PortLo, cl.PortHi)))
}

func (cl *Client) addr(now time.Time) string {
	h := cl.hosts()
	return cl.addrFor(h[int(cl.cur.Load())%len(h)], now)
}

// connect перебирает серверы начиная с последнего рабочего; успешный запоминается.
func (cl *Client) connect(now time.Time) (net.Conn, error) {
	h := cl.hosts()
	if len(h) == 0 {
		return nil, errors.New("не задан сервер")
	}
	start := int(cl.cur.Load())
	var last error
	for i := 0; i < len(h); i++ {
		idx := (start + i) % len(h)
		c, err := net.DialTimeout("tcp", cl.addrFor(h[idx], now), 6*time.Second)
		if err == nil {
			cl.cur.Store(int32(idx))
			return c, nil
		}
		last = err
	}
	return nil, last
}

// Dial открывает соединение с сервером: отправляет ClientHello с нашей проверкой внутри. Ответ сервера
// (ServerHello и ChangeCipherSpec) читается лениво, поэтому данные можно слать сразу, без лишней задержки.
func (cl *Client) Dial() (*secureConn, error) {
	now := time.Now()
	ke := epochKey(cl.Key, epochDay(now))
	list := cl.SNI
	if len(list) == 0 {
		list = DefaultSNI
	}
	c, err := cl.connect(now)
	if err != nil {
		return nil, err
	}
	cn := make([]byte, 16)
	crand.Read(cn)
	if _, err := c.Write(buildClientHello(ke, cn, now, sniFor(ke, list))); err != nil {
		c.Close()
		return nil, err
	}
	sc := newSecure(c, deriveKey(ke, cn, "c2s"), deriveKey(ke, cn, "s2c"), newShaper(profileFor(ke, cn)))
	sc.skip = true
	return sc, nil
}

func (cl *Client) ServeTCP(l net.Listener) {
	for {
		lc, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer lc.Close()
			sc, err := cl.Dial()
			if err != nil {
				log.Printf("соединение: %v", err)
				return
			}
			defer sc.Close()
			go sc.keepalive()
			pipe(sc, tcpHalf{lc.(*net.TCPConn)})
		}()
	}
}
