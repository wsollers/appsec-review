package main

import "example.com/vuln"

func unused(input string) []string { return vuln.Tokenize(input) }
