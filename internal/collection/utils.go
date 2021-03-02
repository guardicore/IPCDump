package collection

import (
	"fmt"
	"strings"

	"honnef.co/go/netdb"
)

func nullStr(s []byte) string {
	return strings.TrimRight(string(s), "\x00")
}

func commStr(comm [16]byte) string {
	return nullStr(comm[:])
}

func servName(proto uint8, port uint16) string {
	protoEnt := netdb.GetProtoByNumber((int)(proto))
	if protoEnt == nil {
		return fmt.Sprintf("%d", port)
	}
	servEnt := netdb.GetServByPort((int)(port), protoEnt)
	if servEnt == nil {
		return fmt.Sprintf("%d/%s", port, protoEnt.Name)
	}
	return servEnt.Name
}
