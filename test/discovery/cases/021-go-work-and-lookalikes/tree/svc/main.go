package main

import (
	"example.test/dep"
	"example.test/lib"
)

func main() {
	println(lib.Name(), dep.Version())
}
