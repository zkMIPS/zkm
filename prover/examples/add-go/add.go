package main

import "github.com/zkMIPS/zkm/go-runtime/zkm_runtime"

type DataId uint32

// use iota to create enum
const (
	TYPE1 DataId = iota
	TYPE2
	TYPE3
)

type Data struct {
	Input1  [10]byte
	Input2  uint8
	Input3  int8
	Input4  uint16
	Input5  int16
	Input6  uint32
	Input7  int32
	Input8  uint64
	Input9  int64
	Input10 []byte
	Input11 DataId
	Input12 string
}

func main() {
	a := zkm_runtime.Read[Data]()
	a.Input1[0] = a.Input1[0] + a.Input1[1]
	a.Input2 = a.Input2 + a.Input2
	a.Input3 = a.Input3 + a.Input3
	a.Input4 = a.Input4 + a.Input4
	a.Input5 = a.Input5 + a.Input5
	a.Input6 = a.Input6 + a.Input6
	a.Input7 = a.Input7 + a.Input7
	a.Input8 = a.Input8 + a.Input8
	a.Input9 = a.Input9 + a.Input9
	if a.Input11 != TYPE3 {
		println("enum type error")
	}
	if a.Input12 != "hello" {
		println("string type error")
	}
	a.Input10[0] = a.Input10[0] + a.Input10[1]
	zkm_runtime.Commit[Data](a)
}
