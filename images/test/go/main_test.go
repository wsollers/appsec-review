package main

import "testing"

func TestMessage(t *testing.T) {
	if Message() != "hello from go" {
		t.Fatalf("unexpected message: %q", Message())
	}
}
