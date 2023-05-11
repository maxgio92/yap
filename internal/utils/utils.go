package utils

import (
	"fmt"
	"os"
)

func Fail(a ...any) {
	fmt.Println(a)
	os.Exit(1)
}

func CheckErr(err error) {
	if err != nil {
		Fail(err)
	}
}
