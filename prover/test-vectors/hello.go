package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("hello world")
	fmt.Println("Args number:", len(os.Args))
	fmt.Println(os.Args)
	for k, v := range os.Args {
		fmt.Printf("args[%v]=[%v]\n", k, v)
	}
}
