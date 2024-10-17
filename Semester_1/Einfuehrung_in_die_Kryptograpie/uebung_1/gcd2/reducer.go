package main

func reduce[T, M any](s []T, f func(M, T) M, initVal M) M {
	acc := initVal

	for _, v := range s {
		acc = f(acc, v)
	}
	return acc
}
