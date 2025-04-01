package main

import (
	"C"
)

//import "fmt"

var prover = &SnarkProver{}

//export Stark2Snark
func Stark2Snark(keypath *C.char, inputdir *C.char, outputdir *C.char, result **C.char) C.int {
	// Convert C strings to Go strings
	keyPath := C.GoString(keypath)
	inputDir := C.GoString(inputdir)
	outputDir := C.GoString(outputdir)

	err := prover.Prove(keyPath, inputDir, outputDir)
	if err != nil {
		//fmt.Printf("Stark2Snark error: %v\n", err)
		cErrMsg := C.CString(err.Error())
		*result = cErrMsg
		return -1
	}
	return 0
}

//export  SetupAndGenerateSolVerifier
func SetupAndGenerateSolVerifier(inputdir *C.char, result **C.char) C.int {
	// Convert C strings to Go strings
	inputDir := C.GoString(inputdir)
	var prover SnarkProver
	err := prover.SetupAndGenerateSolVerifier(inputDir)
	if err != nil {
		//fmt.Printf("Setup error: %v\n", err)
		cErrMsg := C.CString(err.Error())
		*result = cErrMsg
		return -1
	}
	return 0
}

func main() {}
