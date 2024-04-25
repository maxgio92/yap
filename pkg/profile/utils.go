package profile

import (
	"encoding/binary"
	"fmt"
)

func clen(n []byte) int {
	for i := 0; i < len(n); i++ {
		if n[i] == 0 {
			return i
		}
	}
	return len(n)
}

func printHexMapKey(k uint32) string {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, k)
	s := "map key="
	for _, v := range buf {
		s += fmt.Sprintf("0x%x ", v)
	}
	return s
}
