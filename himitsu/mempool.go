package himitsu

import (
	"github.com/google/btree"
	"golang.org/x/crypto/blake2b"
	"math/big"
)

var _ btree.Item = (*MempoolItem)(nil)

type MempoolItem struct {
	index *big.Int
	id    [blake2b.Size256]byte
}

func (m MempoolItem) Less(than btree.Item) bool {
	return m.index.Cmp(than.(MempoolItem).index) < 0
}
