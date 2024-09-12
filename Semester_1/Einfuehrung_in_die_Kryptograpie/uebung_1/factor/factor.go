package main

import (
	"fmt"
	"os"
	"strconv"
)

func main(){
	arg := os.Args[1:]

	n, err := strconv.Atoi(arg[0])

	if err != nil{
		fmt.Println("The entered value is not a valid integer!")
	} else {
		f := factor(n)
		res := ""
		for i := 0; i < len(f); i++ {
			if i == 0{
				res = res + (strconv.Itoa(f[i]))
			} else {
				res = res + "*" + strconv.Itoa(f[i])
			}
		}
		fmt.Println(res)
	}
}

func factor(n int) (pf []int) {
	for n % 2 == 0{
		pf = append(pf, 2)
		n = n / 2
	}

	for i := 3; i*i <= n; i = i + 2 {
		for n % i == 0{
			pf = append(pf, i)
			n = n / i
		}
	}

	if n > 2 {
		pf = append(pf, n)
	}

	return
}