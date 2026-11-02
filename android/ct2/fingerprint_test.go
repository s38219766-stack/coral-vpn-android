package ct2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

// features — признаки ClientHello, нужные для отпечатков JA3/JA4 и для сравнения.
type features struct {
	ciphers, exts, groups, sigalgs, versions, shareGroups []int
	alpn                                                  []string
	sni                                                   bool
	echLen                                                int
	extLen                                                map[int]int
}

func isGreaseVal(v int) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func u16s(b []byte) (out []int) {
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, int(binary.BigEndian.Uint16(b[i:])))
	}
	return
}

// parseFeatures разбирает сообщение ClientHello (без заголовка записи).
func parseFeatures(raw []byte) (*features, error) {
	f := &features{extLen: map[int]int{}}
	if len(raw) < 40 || raw[0] != 1 {
		return nil, errHello
	}
	b := raw[4:]
	p := 2 + 32
	p += 1 + int(b[p])
	cl := int(binary.BigEndian.Uint16(b[p:]))
	f.ciphers = u16s(b[p+2 : p+2+cl])
	p += 2 + cl
	p += 1 + int(b[p])
	el := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	for e := b[p : p+el]; len(e) >= 4; {
		t, l := int(binary.BigEndian.Uint16(e)), int(binary.BigEndian.Uint16(e[2:]))
		d := e[4 : 4+l]
		f.exts = append(f.exts, t)
		f.extLen[t] = l
		switch t {
		case 0x0000:
			f.sni = true
		case 0x000a:
			f.groups = u16s(d[2:])
		case 0x000d:
			f.sigalgs = u16s(d[2:])
		case 0x002b:
			f.versions = u16s(d[1:])
		case 0x0010:
			for q := 2; q < l; {
				n := int(d[q])
				f.alpn = append(f.alpn, string(d[q+1:q+1+n]))
				q += 1 + n
			}
		case extKeyShare:
			for q := 2; q+4 <= l; {
				kl := int(binary.BigEndian.Uint16(d[q+2:]))
				f.shareGroups = append(f.shareGroups, int(binary.BigEndian.Uint16(d[q:])))
				q += 4 + kl
			}
		case extECH:
			f.echLen = l
		}
		e = e[4+l:]
	}
	return f, nil
}

func noGrease(v []int) (out []int) {
	for _, x := range v {
		if !isGreaseVal(x) {
			out = append(out, x)
		}
	}
	return
}

func hex4(v []int) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprintf("%04x", x)
	}
	return strings.Join(s, ",")
}

func h12(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:])[:12] }

// ja4 — отпечаток JA4 по описанию FoxIO (TCP, TLS).
func (f *features) ja4() string {
	ver := "00"
	best := 0
	for _, v := range noGrease(f.versions) {
		if v > best {
			best = v
		}
	}
	switch best {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	}
	sni := "i"
	if f.sni {
		sni = "d"
	}
	ciph := noGrease(f.ciphers)
	exts := noGrease(f.exts)
	alpn := "00"
	if len(f.alpn) > 0 && len(f.alpn[0]) > 0 {
		a := f.alpn[0]
		alpn = string(a[0]) + string(a[len(a)-1])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", ver, sni, len(ciph), len(exts), alpn)
	sc := append([]int{}, ciph...)
	sort.Ints(sc)
	var se []int
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			se = append(se, e)
		}
	}
	sort.Ints(se)
	cpart := hex4(se)
	if len(f.sigalgs) > 0 {
		cpart += "_" + hex4(f.sigalgs)
	}
	return a + "_" + h12(hex4(sc)) + "_" + h12(cpart)
}

func (f *features) summary() string {
	return fmt.Sprintf("ciphers=%d exts=%d groups=%s sigalgs=%d alpn=%v versions=%s shares=%s ech=%d",
		len(noGrease(f.ciphers)), len(noGrease(f.exts)), hex4(noGrease(f.groups)), len(f.sigalgs), f.alpn, hex4(noGrease(f.versions)), hex4(noGrease(f.shareGroups)), f.echLen)
}

func TestJA4StableAcrossHellos(t *testing.T) {
	cc, _, _ := configs(t)
	seen := map[string]int{}
	for i := 0; i < 50; i++ {
		rec, _, err := buildHello(cc, "www.yandex.ru")
		if err != nil {
			t.Fatal(err)
		}
		f, err := parseFeatures(rec[5:])
		if err != nil {
			t.Fatal(err)
		}
		seen[f.ja4()]++
	}
	if len(seen) != 1 {
		t.Fatalf("JA4 нестабилен между соединениями (у Chrome он постоянен): %v", seen)
	}
	for k := range seen {
		t.Log("JA4 нашего ClientHello:", k)
	}
}

// Сравнение с настоящим Chrome, установленным в системе (CT2_CHROME=1): ловим его ClientHello на локальном порту.
func TestCompareWithRealChrome(t *testing.T) {
	if os.Getenv("CT2_CHROME") == "" {
		t.Skip("CT2_CHROME не задан")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				var h [5]byte
				if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 0x16 {
					return
				}
				b := make([]byte, binary.BigEndian.Uint16(h[3:]))
				if _, err := io.ReadFull(c, b); err == nil {
					got <- b
				}
			}()
		}
	}()
	dir := t.TempDir()
	cmd := exec.Command("google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--user-data-dir="+dir,
		"--host-resolver-rules=MAP www.yandex.ru 127.0.0.1", "--disable-features=NetworkService,HttpsUpgrades", "--virtual-time-budget=4000",
		"--dump-dom", fmt.Sprintf("https://www.yandex.ru:%d/", port))
	go cmd.Run()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	var chrome *features
	select {
	case b := <-got:
		chrome, err = parseFeatures(b)
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Chrome не прислал ClientHello")
	}
	cc, _, _ := configs(t)
	rec, _, _ := buildHello(cc, "www.yandex.ru")
	ours, _ := parseFeatures(rec[5:])
	t.Logf("Chrome: %s", chrome.summary())
	t.Logf("Ours:   %s", ours.summary())
	t.Logf("sigalgs Chrome: %s", hex4(chrome.sigalgs))
	t.Logf("sigalgs Ours:   %s", hex4(ours.sigalgs))
	t.Logf("JA4 Chrome: %s", chrome.ja4())
	t.Logf("JA4 Ours:   %s", ours.ja4())
	setOf := func(v []int) map[int]bool {
		m := map[int]bool{}
		for _, x := range noGrease(v) {
			m[x] = true
		}
		return m
	}
	cs, os2 := setOf(chrome.exts), setOf(ours.exts)
	var onlyC, onlyO []string
	for k := range cs {
		if !os2[k] {
			onlyC = append(onlyC, fmt.Sprintf("%#04x", k))
		}
	}
	for k := range os2 {
		if !cs[k] {
			onlyO = append(onlyO, fmt.Sprintf("%#04x", k))
		}
	}
	sort.Strings(onlyC)
	sort.Strings(onlyO)
	t.Logf("расширения только у Chrome: %v; только у нас: %v", onlyC, onlyO)
	t.Logf("длина ECH: Chrome %d, у нас %d", chrome.echLen, ours.echLen)
	if chrome.ja4() != ours.ja4() {
		t.Fatalf("JA4 отличается от установленного Chrome: обновите профиль/ChromeSigAlgs")
	}
}
