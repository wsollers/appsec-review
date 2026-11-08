package main

// go:build experimental  (a space after the slashes: a comment, not a constraint)

//go:build never
// a constraint after the package clause is ignored by the go tool

func label() string { return "label" }
