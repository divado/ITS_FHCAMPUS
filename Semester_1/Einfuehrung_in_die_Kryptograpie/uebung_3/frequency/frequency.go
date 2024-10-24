package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	file := os.Args[1:]

	dat, err := os.ReadFile(file[0])
	check(err)

	charSum, m := getCharMapAndCharSum(dat)

	sortAndPrintFrequencies(charSum, m)
}

func getCharMapAndCharSum(dat []byte) (int, map[string]int) {
	regex, _ := regexp.Compile("[a-z]+")
	m := make(map[string]int)

	for char := range string(dat) {
		curr := strings.ToLower(string(dat[char]))

		if regex.MatchString(curr) {
			m[curr]++
		}
	}

	var charSum int
	for key := range m {
		charSum += m[key]
	}

	return charSum, m
}

func sortAndPrintFrequencies(charSum int, m map[string]int) {
	keys := make([]string, 0, len(m))

	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for key := range keys {
		var perc float32 = float32(m[keys[key]]) / float32(charSum) * 100.00
		fmt.Printf("%s\t %d\t %.2f%%\n", keys[key], m[keys[key]], perc)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
