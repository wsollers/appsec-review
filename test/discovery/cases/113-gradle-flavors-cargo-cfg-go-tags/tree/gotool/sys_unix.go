//go:build !windows

package main

func osName() string { return "unix" }
