//go:build !linux

package bpf

import "time"

func monotonicNowNS() (uint64, error) {
	return uint64(time.Now().UnixNano()), nil
}
