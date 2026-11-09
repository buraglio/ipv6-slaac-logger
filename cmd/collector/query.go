//go:build !windows

package main

import (
	"errors"
	"io"
)

func queryCmd(args []string, w io.Writer) error { return errors.New("query: implemented in Task 13") }
