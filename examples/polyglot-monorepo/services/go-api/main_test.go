package main

import "testing"

func TestGreeting(t *testing.T) {
	if got := Greeting(""); got != "hello, world" {
		t.Fatalf("got %q", got)
	}
	if got := Greeting("afg"); got != "hello, afg" {
		t.Fatalf("got %q", got)
	}
}
