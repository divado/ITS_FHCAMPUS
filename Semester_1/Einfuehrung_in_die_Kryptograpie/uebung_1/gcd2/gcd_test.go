package main

import "testing"

func TestGcd(t *testing.T) {
	got := GCD2(factor(819), factor(49))
	want := 7

	if got != want {
		t.Errorf("got %d, wanted %d", got, want)
	}
}
