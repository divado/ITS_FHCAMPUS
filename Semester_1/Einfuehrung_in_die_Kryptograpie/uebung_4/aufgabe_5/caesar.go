package main

import (
	"fmt"
	"os"
)

func caesar(input string, rot int) string {
	var output []rune

	for _, char := range input {
		base := 0
		switch {
		case char >= 'A' && char <= 'Z':
			base = int('A')
		case char >= 'a' && char <= 'z':
			base = int('a')
		}

		if base != 0 {
			char = rune(((int(char) - base + rot) % 26) + base)
		}

		output = append(output, char)
	}
	return string(output)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	args := os.Args[1:]

	dat, err := os.ReadFile(args[0])
	check(err)

	input := string(dat)

	for i := range 25 {
		fmt.Printf("Key: %d \n%s\n\n", i, caesar(input, i))
	}
}
