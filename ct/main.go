// ct — слой формы трафика Coral Transport. Режимы: server и client. Подробности: docs/coral-transport.md
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("использование: ct server|client [флаги]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", ":9500", "адрес TCP и UDP")
		up := fs.String("upstream", "127.0.0.1:8388", "локальный Shadowsocks")
		fb := fs.String("fallback", "127.0.0.1:443", "настоящий сайт для чужих")
		master := fs.String("master", os.Getenv("CT_MASTER"), "общий секрет, hex")
		users := fs.String("users", "users.json", "JSON-список имён")
		sni := fs.String("sni", "", "имена маскировки через запятую (по умолчанию встроенный список; на клиенте и сервере одинаково)")
		fs.Parse(os.Args[2:])
		m, err := hex.DecodeString(*master)
		if err != nil || len(m) < 16 {
			log.Fatal("нужен -master (hex, от 16 байт)")
		}
		s := NewServer(m, *up, *fb)
		if *sni != "" {
			s.SNI = strings.Split(*sni, ",")
		}
		go s.LoadUsers(*users)
		l, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		ua, _ := net.ResolveUDPAddr("udp", *listen)
		pc, err := net.ListenUDP("udp", ua)
		if err != nil {
			log.Fatal(err)
		}
		go s.ServeUDP(pc)
		log.Printf("ct server на %s", *listen)
		s.ServeTCP(l)
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:19500", "локальный адрес для sing-box (TCP и UDP)")
		remote := fs.String("remote", "", "сервер (хост)")
		ports := fs.String("ports", "9500:9500", "диапазон портов сервера lo:hi")
		key := fs.String("key", os.Getenv("CT_KEY"), "ключ пользователя, hex")
		sni := fs.String("sni", "", "имена маскировки через запятую (как на сервере)")
		fs.Parse(os.Args[2:])
		k, err := hex.DecodeString(*key)
		if err != nil || len(k) < 16 || *remote == "" {
			log.Fatal("нужны -remote и -key")
		}
		lo, hi := 0, 0
		p := strings.SplitN(*ports, ":", 2)
		lo, _ = strconv.Atoi(p[0])
		hi = lo
		if len(p) == 2 {
			hi, _ = strconv.Atoi(p[1])
		}
		cl := &Client{Remote: *remote, PortLo: lo, PortHi: hi, Key: k}
		if *sni != "" {
			cl.SNI = strings.Split(*sni, ",")
		}
		l, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatal(err)
		}
		ua, _ := net.ResolveUDPAddr("udp", *listen)
		pc, err := net.ListenUDP("udp", ua)
		if err != nil {
			log.Fatal(err)
		}
		go cl.ServeUDP(pc)
		log.Printf("ct client на %s → %s", *listen, *remote)
		cl.ServeTCP(l)
	default:
		fmt.Println("использование: ct server|client [флаги]")
		os.Exit(2)
	}
}
