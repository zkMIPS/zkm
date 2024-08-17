//go:build mips
// +build mips

package zkm_runtime

func SyscallWrite(fd int, write_buf []byte, nbytes int) int
func SyscallHintLen() int
func SyscallHintRead(ptr []byte, len int)

func Read[T any]() T {
	len := SyscallHintLen()
	var value []byte
	capacity := (len + 3) / 4 * 4
	value = make([]byte, capacity)
	var result T
	SyscallHintRead(value, len)
	DeserializeData(value[0:len], &result)
	return result
}

func Commit[T any](value T) {
	bytes := MustSerializeData(value)
	length := len(bytes)
	if (length & 3) != 0 {
		d := make([]byte, 4-(length&3))
		bytes = append(bytes, d...)
	}

	SyscallWrite(3, bytes, length)
}
