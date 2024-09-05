package main

import "fmt"

func ExtendedGCD(a, b int) (int, int, int) {
	if a == 0 {
		return b, 0, 1
	}
	gcd, x1, y1 := ExtendedGCD(b%a, a)
	x := y1 - (b/a)*x1
	y := x1
	return gcd, x, y
}

func main() {
	var a, b int
	fmt.Println("Please enter your values for a and b for the euclidian algorithm.")
	fmt.Scanf("%d %d", &a, &b)
	gcd, x, y := ExtendedGCD(a, b)
	fmt.Printf("The GCD of %d and %d is %d, x = %d, y = %d", a, b, gcd, x, y)
}
