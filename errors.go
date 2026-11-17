package main

import "errors"

var (
	errNeedMore   = errors.New("need more")
	errBadVersion = errors.New("unexpected response version")
)
