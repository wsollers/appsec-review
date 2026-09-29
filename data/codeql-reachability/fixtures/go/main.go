package main

import (
	"fmt"
	"os"

	"example.com/vuln"
)

func handle(input string) string { return vuln.Parse(input) }

func main() { fmt.Println(handle(os.Args[1])) }
