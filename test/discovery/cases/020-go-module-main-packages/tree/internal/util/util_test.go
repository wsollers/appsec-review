package util

import "testing"

func TestGreeting(t *testing.T) {
	if Greeting("x") != "hello x" {
		t.Fatal("greeting")
	}
}
