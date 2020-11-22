package main

import (
    "strconv"
)

type uintArrayFlags []uint64

func (i *uintArrayFlags) String() string {
	return ""
}

func (i *uintArrayFlags) Set(value string) error {
    u, err := strconv.ParseUint(value, 0, 32)
    if err != nil {
        return err
    }
	*i = append(*i, u)
	return nil
}

type stringArrayFlags []string

func (i *stringArrayFlags) String() string {
	return ""
}

func (i *stringArrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
