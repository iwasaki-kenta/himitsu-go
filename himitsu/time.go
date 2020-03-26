package himitsu

import (
	"math/rand"
	"time"
)

// Delay simulates a network delay.
func Delay(rate float64) {
	seconds := rand.ExpFloat64() / rate
	time.Sleep(time.Duration(seconds * 1e9))
}
