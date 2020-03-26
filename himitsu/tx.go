package himitsu

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

// Transaction represents a single transaction in the distributed ledger.
// Once created, each transaction is immutable.
type Transaction struct {
	Sender [ed25519.PublicKeySize]byte
	Nonce  uint64

	Block uint64

	ID [blake2b.Size256]byte
}

// NewTransaction creates a new transaction.
func NewTransaction(sender []byte, nonce, block uint64) Transaction {
	t := Transaction{Nonce: nonce, Block: block}

	copy(t.Sender[:], sender)
	t.ID = blake2b.Sum256(t.MarshalBytes())

	return t
}

// ComputeIndex returns the transaction index on the specified block id.
func (t Transaction) ComputeIndex(blockID [blake2b.Size256]byte) *big.Int {
	buf := blake2b.Sum256(append(t.ID[:], blockID[:]...))
	index := (&big.Int{}).SetBytes(buf[:])

	return index
}

// MarshalBytes returns the byte representation of the transaction.
func (t Transaction) MarshalBytes() []byte {
	buf := make([]byte, ed25519.PublicKeySize+8+8)

	copy(buf[:ed25519.PublicKeySize], t.Sender[:])
	binary.BigEndian.PutUint64(buf[ed25519.PublicKeySize:ed25519.PublicKeySize+8], t.Nonce)
	binary.BigEndian.PutUint64(buf[ed25519.PublicKeySize+8:ed25519.PublicKeySize+8+8], t.Block)

	return buf
}

// String returns the hex encoded transaction id.
func (t Transaction) String() string {
	return hex.EncodeToString(t.ID[:])
}
