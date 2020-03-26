package himitsu

import (
	"golang.org/x/crypto/blake2b"
)

// Snowball is a consensus algorithm based on the Avalanche paper,
// with slight modification to add support for non-binary decision.
type Snowball struct {
	Count  uint16
	Counts map[[blake2b.Size256]byte]uint16

	Preferred *Block
	Last      *Block

	Done bool
}

func NewSnowball() *Snowball {
	return &Snowball{Counts: make(map[[blake2b.Size256]byte]uint16)}
}

// Tick runs a single snowball loop to determine which block to finalize on.
func (s *Snowball) Tick(tallies map[[blake2b.Size256]byte]float64, blocks map[[blake2b.Size256]byte]*Block) {
	if s.Done {
		return
	}

	// Get the majority block and its tally
	var majority *Block = nil
	var majorityTally float64 = 0

	for id, tally := range tallies {
		if tally > majorityTally {
			majority, majorityTally = blocks[id], tally
		}
	}

	denom := float64(len(blocks))

	if denom < 2 {
		denom = 2
	}

	// Reset snowball count if condition is not met.
	// This is the non-binary variant of Snowball (in the paper, the condition is SnowballAlpha*SnowballK).
	if majority == nil || majorityTally < SnowballAlpha*2/denom {
		s.Count = 0
		return
	}

	// Set majority block as preferred if its count is higher than the
	// currently preferred block
	s.Counts[majority.ID] += 1
	if s.Counts[majority.ID] > s.Counts[s.Preferred.ID] {
		s.Preferred = majority
	}

	// Keep track of the last preferred block
	if s.Last == nil || majority.ID != s.Last.ID {
		s.Last, s.Count = majority, 1
	} else {
		s.Count += 1

		// Snowball is done when the count is higher than snowball beta parameter
		if s.Count > SnowballBeta {
			s.Preferred, s.Done = majority, true
		}
	}
}

// Reset resets the snowball algorithm.
func (s *Snowball) Reset() {
	s.Preferred = nil
	s.Last = nil

	s.Counts = make(map[[blake2b.Size256]byte]uint16)
	s.Count = 0

	s.Done = false
}
