package main

import (
	"fmt"
	"os"
	"slices"
	"strconv"
)

func GCD2(a, b []int) (gcd int) {
	var commonFacs []int
	gcd = 1

	for _, facA := range a {
		if slices.Contains(b, facA) {
			commonFacs = append(commonFacs, facA)
			b = slices.Delete(b, slices.Index(b, facA), slices.Index(b, facA)+1)
		}
	}

	for _, common := range commonFacs {
		gcd = gcd * common
	}
	return
}

func factor(n int) (pf []int) {
	for n%2 == 0 {
		pf = append(pf, 2)
		n = n / 2
	}

	for i := 3; i*i <= n; i = i + 2 {
		for n%i == 0 {
			pf = append(pf, i)
			n = n / i
		}
	}

	if n > 2 {
		pf = append(pf, n)
	}

	return
}

func main() {
	var a, b int

	args := os.Args[1:]

	a, _ = strconv.Atoi(args[0])
	b, _ = strconv.Atoi(args[1])

	factorsA := factor(a)
	factorsB := factor(b)

	gcd2 := GCD2(factorsA, factorsB)

	fmt.Println(gcd2)
}
