package main

import "testing"

func TestGcd(t *testing.T) {
	got := GCD(15, 50)
	want := 5

	if got != want {
		t.Errorf("got %d, wanted %d", got, want)
	}
}
