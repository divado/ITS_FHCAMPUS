package main

import (
	"fmt"
	"os"
)

func main() {
	file := os.Args[1:]

	dat, err := os.ReadFile(file[0])
	check(err)
	s := string(dat)

	m := make(map[string]int)

	for char := range string(dat) {
		m[string(dat[char])]++
	}

	fmt.Printf("File has length: %v\n", len(s))
	fmt.Println(m)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
