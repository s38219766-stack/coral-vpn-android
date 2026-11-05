package ct2

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func listJSON(t testing.TB, n int) ([]byte, [][]byte) {
	var es []userEntry
	var pubs [][]byte
	for i := 0; i < n; i++ {
		k := newKey(t)
		es = append(es, userEntry{Name: "u", Pub: hex.EncodeToString(k.Public)})
		pubs = append(pubs, k.Public)
	}
	b, _ := json.Marshal(es)
	return b, pubs
}

func TestUserListReplaceAndGuards(t *testing.T) {
	u := &UserList{Logf: func(string, ...any) {}}
	b, pubs := listJSON(t, 3)
	if err := u.Replace(b); err != nil || u.Len() != 3 || !u.Allowed(pubs[0]) || u.Allowed([]byte("xx")) {
		t.Fatal("replace failed", err)
	}
	if err := u.Replace([]byte("[]")); err != ErrEmptyList || u.Len() != 3 {
		t.Fatal("empty list must be rejected and the old list kept:", err)
	}
	if err := u.Replace([]byte("not json")); err == nil || u.Len() != 3 {
		t.Fatal("bad json must be rejected")
	}
	if err := u.Replace([]byte(`[{"name":"x","pub":"zz"}]`)); err == nil || u.Len() != 3 {
		t.Fatal("list without valid keys must be rejected")
	}
	b2, _ := listJSON(t, 1)
	if err := u.Replace(b2); err != nil || u.Len() != 1 || u.Allowed(pubs[0]) {
		t.Fatal("a smaller valid list must replace the old one (revocation):", err)
	}
}

func TestUserListSyncTokenETagAndOutage(t *testing.T) {
	body, pubs := listJSON(t, 2)
	var hits, notMod atomic.Int32
	down := atomic.Bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			notMod.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(body)
	}))
	defer srv.Close()
	u := &UserList{Logf: func(string, ...any) {}}
	if _, err := u.Fetch(context.Background(), srv.Client(), srv.URL, "wrong"); err == nil {
		t.Fatal("wrong token must fail")
	}
	if u.Len() != 0 {
		t.Fatal("nothing must be loaded with a wrong token")
	}
	ch, err := u.Fetch(context.Background(), srv.Client(), srv.URL, "secret")
	if err != nil || !ch || u.Len() != 2 || !u.Allowed(pubs[1]) {
		t.Fatal("fetch failed", ch, err)
	}
	ch, err = u.Fetch(context.Background(), srv.Client(), srv.URL, "secret")
	if err != nil || ch || notMod.Load() != 1 {
		t.Fatal("second fetch must be 304 / unchanged", ch, err, notMod.Load())
	}
	down.Store(true)
	if _, err := u.Fetch(context.Background(), srv.Client(), srv.URL, "secret"); err == nil || u.Len() != 2 {
		t.Fatal("panel outage must keep the last list")
	}
}

func TestUserListRunUsesCacheAndAppliesRevocation(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "sub", "users.cache.json")
	b1, p1 := listJSON(t, 2)
	b2, p2 := listJSON(t, 1)
	var mu sync.Mutex
	cur, et := b1, `"a"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("If-None-Match") == et {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", et)
		w.Write(cur)
	}))
	defer srv.Close()
	u := &UserList{Logf: func(string, ...any) {}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		u.Run(ctx, SyncConfig{URL: srv.URL, Token: "t", Interval: 30 * time.Millisecond, CachePath: cache, Client: srv.Client()})
		close(done)
	}()
	waitFor := func(cond func() bool) {
		for i := 0; i < 200; i++ {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timeout waiting for condition")
	}
	waitFor(func() bool { return u.Len() == 2 })
	if !u.Allowed(p1[0]) {
		t.Fatal("first list not applied")
	}
	waitFor(func() bool { _, err := os.Stat(cache); return err == nil }) // кэш записан
	mu.Lock()
	cur, et = b2, `"b"`
	mu.Unlock()
	waitFor(func() bool { return u.Len() == 1 && u.Allowed(p2[0]) && !u.Allowed(p1[0]) }) // отзыв ключей применился
	cancel()
	<-done
	// после перезапуска при недоступной панели узел берёт кэш
	srv.Close()
	u2 := &UserList{Logf: func(string, ...any) {}}
	ctx2, cancel2 := context.WithCancel(context.Background())
	go u2.Run(ctx2, SyncConfig{URL: "http://127.0.0.1:1/", Token: "t", Interval: time.Hour, CachePath: cache, Client: &http.Client{Timeout: 200 * time.Millisecond}})
	waitFor(func() bool { return u2.Len() == 1 && u2.Allowed(p2[0]) })
	cancel2()
}

func TestRegistrySweepClosesRevokedSessions(t *testing.T) {
	cc, sc, ck := configs(t)
	cli, srv, ce, se := pair(t, cc, sc)
	if ce != nil || se != nil {
		t.Fatal(ce, se)
	}
	var reg Registry
	remove := reg.Add(srv)
	defer remove()
	if n := reg.Sweep(func(p []byte) bool { return string(p) == string(ck.Public) }); n != 0 || reg.Len() != 1 {
		t.Fatal("allowed session must stay open")
	}
	if n := reg.Sweep(func([]byte) bool { return false }); n != 1 {
		t.Fatal("revoked session must be closed, got", n)
	}
	// клиент должен заметить закрытие: чтение завершается ошибкой/EOF
	done := make(chan error, 1)
	go func() { _, err := cli.Read(make([]byte, 8)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("client read must fail after the session was closed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not notice the closed session")
	}
}
