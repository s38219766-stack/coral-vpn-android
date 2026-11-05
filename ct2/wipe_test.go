package ct2

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

// После рукопожатия эфемерные секреты обеих сторон должны быть затёрты, а сеанс при этом работать.
func TestHandshakeWipesEphemeralSecrets(t *testing.T) {
	var mu sync.Mutex
	var keys [][]byte
	debugEph = func(k []byte) { mu.Lock(); keys = append(keys, k); mu.Unlock() }
	defer func() { debugEph = nil }()
	cc, sc, _ := configs(t)
	cli, srv, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	go srv.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := cli.Read(buf); err != nil || string(buf) != "hi" {
		t.Fatal("session broken after wipe:", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(keys) < 2 {
		t.Fatalf("expected ephemeral keys of both sides, got %d", len(keys))
	}
	zero := make([]byte, 32)
	for i, k := range keys {
		if !bytes.Equal(k, zero) {
			t.Fatalf("ephemeral key %d not wiped", i)
		}
	}
}

func TestWipeAndConfigWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal("Wipe")
	}
	cc, _, _ := configs(t)
	cc.Wipe()
	if !bytes.Equal(cc.Static.Private, make([]byte, len(cc.Static.Private))) {
		t.Fatal("Config.Wipe")
	}
}

func TestRandomPadderProfilesVaryAndStayValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p := NewRandomPadder(rand.New(rand.NewSource(int64(i)))).(BucketPadder)
		prev := 0
		for _, b := range p.Buckets {
			if b <= prev || b > 1400 || b%8 != 0 {
				t.Fatalf("bad bucket %v", p.Buckets)
			}
			prev = b
		}
		seen[fmt.Sprint(p.Buckets)] = true
	}
	if len(seen) < 50 {
		t.Fatalf("profiles are not varied enough: %d distinct of 200", len(seen))
	}
}
