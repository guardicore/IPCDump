package collection

// irresponsibly stolen from os/signal/internal/pty/pty.go
// this file is necessary because golang doesn't allow direct importing of cgo from test packages
// (not sure why this is)

/*
#define _XOPEN_SOURCE 600
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
*/
import "C"

import (
    "syscall"
    "fmt"
    "os"
)

type PtyError struct {
	FuncName    string
	ErrorString string
	Errno       syscall.Errno
}

func ptyError(name string, err error) *PtyError {
	return &PtyError{name, err.Error(), err.(syscall.Errno)}
}

func (e *PtyError) Error() string {
	return fmt.Sprintf("%s: %s", e.FuncName, e.ErrorString)
}

func (e *PtyError) Unwrap() error { return e.Errno }

// Open returns a control pty and the name of the linked process tty.
func OpenTestPty() (pty *os.File, processTTY string, err error) {
	m, err := C.posix_openpt(C.O_RDWR)
	if err != nil {
		return nil, "", ptyError("posix_openpt", err)
	}
	if _, err := C.grantpt(m); err != nil {
		C.close(m)
		return nil, "", ptyError("grantpt", err)
	}
	if _, err := C.unlockpt(m); err != nil {
		C.close(m)
		return nil, "", ptyError("unlockpt", err)
	}
	processTTY = C.GoString(C.ptsname(m))
	return os.NewFile(uintptr(m), "pty"), processTTY, nil
}


