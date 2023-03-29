package utils

import (
	"math"
	_ "unsafe"
)

//go:linkname now time.now
func now() (sec int64, nsec int32, mono int64)

func GetDiffWallMono() float64 {
	sec, nsec, mono := now()
	wall := uint((float64(sec) + float64(nsec)*math.Pow(10, -10)) * math.Pow(10, 10))
	return float64((wall - uint(mono))) * math.Pow(10, -10)
}
