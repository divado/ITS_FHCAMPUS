package main

import (
	"fmt"
	"os"
	"strconv"
)

func GCD(a, b int) (gcd int) {
	if a == 0 {
		return b
	}
	gcd = GCD(b%a, a)
	return 
}

func main() {
	var a, b int

	args := os.Args[1:]

	a, _ = strconv.Atoi(args[0])
	b, _ = strconv.Atoi(args[1])


	gcd := GCD(a, b)
	fmt.Println(gcd)
}