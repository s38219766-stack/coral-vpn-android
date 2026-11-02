// ct2key — генерация ключей: `ct2key server` (ключ узла) и `ct2key user ИМЯ` (ключ пользователя; публичная часть идёт в users.json).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/flynn/noise"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "server" && os.Args[1] != "user") {
		fmt.Fprintln(os.Stderr, "использование: ct2key server | ct2key user ИМЯ")
		os.Exit(2)
	}
	k, err := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s).GenerateKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}
	name := "server"
	if os.Args[1] == "user" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "укажите имя пользователя")
			os.Exit(2)
		}
		name = os.Args[2]
	}
	fmt.Printf("name:    %s\nprivate: %s   # хранить в секрете\npublic:  %s\n", name, hex.EncodeToString(k.Private), hex.EncodeToString(k.Public))
}
