package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	identity := uuid.NewSHA1(uuid.NameSpaceDNS, []byte("appsec fixture"))
	fmt.Println("appsec fixture", identity, nativeSum())
}
