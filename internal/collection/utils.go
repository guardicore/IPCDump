package collection

import (
    "strings"
)

func nullStr(s []byte) string {
    return strings.TrimRight(string(s), "\x00")
}

func commStr(comm [16]byte) string {
    return nullStr(comm[:])
}
