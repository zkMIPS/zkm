package main

import (
	"bytes"
	"crypto/sha256"
	"log"

	"github.com/zkMIPS/zkm/go-runtime/zkm_runtime"
)

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

	data := []byte(a.Input12)
	hash := sha256.Sum256(data)

	assertEqual(hash[:], a.Input10)

	zkm_runtime.Commit[Data](a)
}

func assertEqual(a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		log.Fatal("%x != %x", a, b)
	}
}
