package main

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
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

	mu      sync.Mutex
	udpPort int
	udpAt   time.Time
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

// pickPort — случайный порт из диапазона: каждое новое соединение идёт на другой порт, поэтому блокировка отдельных портов
// почти ничего не отнимает (сервер принимает весь диапазон одинаково).
func (cl *Client) pickPort() int {
	if cl.PortHi <= cl.PortLo {
		return cl.PortLo
	}
	return cl.PortLo + rand.IntN(cl.PortHi-cl.PortLo+1)
}

func (cl *Client) addrFor(host string, _ time.Time) string {
	return net.JoinHostPort(host, fmt.Sprint(cl.pickPort()))
}

// addr — адрес для UDP: порт «прыгает» раз в минуту (в пределах минуты соответствие в NAT оператора не меняется).
func (cl *Client) addr(now time.Time) string {
	h := cl.hosts()
	cl.mu.Lock()
	if cl.udpPort == 0 || now.Sub(cl.udpAt) > time.Minute {
		cl.udpPort, cl.udpAt = cl.pickPort(), now
	}
	port := cl.udpPort
	cl.mu.Unlock()
	return net.JoinHostPort(h[int(cl.cur.Load())%len(h)], fmt.Sprint(port))
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
		for try := 0; try < 2; try++ { // два разных порта на сервер, потом следующий сервер
			c, err := net.DialTimeout("tcp", cl.addrFor(h[idx], now), 5*time.Second)
			if err == nil {
				cl.cur.Store(int32(idx))
				return c, nil
			}
			last = err
		}
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
