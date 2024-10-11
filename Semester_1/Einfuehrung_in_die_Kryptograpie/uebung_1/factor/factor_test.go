package main

import "testing"

func TestFactor(t *testing.T) {
	got := factor(15)
	want := []int{3, 5}

	if len(got) != len(want) {
		t.Errorf("got %d, wanted %d", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("got %d, wanted %d", got, want)
		}
	}
}
