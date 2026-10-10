package main

/*
static int fixture_add(int a, int b) { return a + b; }
*/
import "C"

func nativeSum() int {
	return int(C.fixture_add(2, 3))
}
