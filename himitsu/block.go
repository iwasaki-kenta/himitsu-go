package himitsu

import (
	"encoding/binary"
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
)

// A Block contains a list of finalized transactions.
type Block struct {
	Index        uint64
	Transactions [][blake2b.Size256]byte

	ID [blake2b.Size256]byte
}

// NewBlock creates a new block.
func NewBlock(index uint64, transactions ...[blake2b.Size256]byte) Block {
	b := Block{Index: index, Transactions: transactions}
	b.ID = blake2b.Sum256(b.MarshalBytes())

	return b
}

// MarshalBytes returns the byte representation of the block.
func (b Block) MarshalBytes() []byte {
	buf := make([]byte, 8+4+len(b.Transactions)*blake2b.Size256)
	binary.BigEndian.PutUint64(buf[:8], b.Index)
	binary.BigEndian.PutUint32(buf[8:8+4], uint32(len(b.Transactions)))

	for i, id := range b.Transactions {
		copy(buf[8+4+blake2b.Size256*i:8+4+blake2b.Size256*(i+1)], id[:])
	}

	return buf
}

// String returns the hex encoded block id.
func (b Block) String() string {
	return hex.EncodeToString(b.ID[:])
}
