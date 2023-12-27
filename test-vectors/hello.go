package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("hello world")
	// 获取命令行参数
	fmt.Println("命令行参数数量:", len(os.Args))
	fmt.Println(os.Args)
	for k, v := range os.Args {
		fmt.Printf("args[%v]=[%v]\n", k, v)
	}
}
