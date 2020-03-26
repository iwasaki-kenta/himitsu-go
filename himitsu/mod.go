package himitsu

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"math/rand"
	"sync"

	"github.com/google/btree"
	"golang.org/x/crypto/blake2b"
)

// Node represents a single node in the peer-to-peer network
// of the distributed ledger. Since this is just a simulation,
// no overlay network is maintained. In practice, S/Kademlia
// is used.
type Node struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey

	Blocks     []Block
	BlocksLock sync.RWMutex

	Transactions     map[[blake2b.Size256]byte]Transaction
	TransactionsLock sync.RWMutex

	Mempool     *btree.BTree
	MempoolLock sync.RWMutex

	Snowball     *Snowball
	SnowballLock sync.RWMutex

	Nonce uint64
	Stake uint64

	Net *Network
	ID  int
}

// NewNode creates a new node with a generated keys.
func NewNode(net *Network, id int) (*Node, error) {
	var err error

	n := &Node{
		Transactions: make(map[[blake2b.Size256]byte]Transaction),
		Mempool:      btree.New(32),
		Snowball:     NewSnowball(),
		Net:          net,
		ID:           id,
	}

	// Generate a pair of edwards25519 key, which are used for
	// hashing transaction ID
	n.PublicKey, n.PrivateKey, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate node wallet: %w", err)
	}

	return n, nil
}

// NewTransaction creates a new transaction with the node as its sender.
func (n *Node) NewTransaction() Transaction {
	tx := NewTransaction(n.PublicKey, n.Nonce, n.LastBlockIndex()+1)
	n.Nonce++

	return tx
}

var EmptyBlockID [blake2b.Size256]byte

// LastBlockID returns the last block ID that has been finalized on this node.
func (n *Node) LastBlockID() [blake2b.Size256]byte {
	n.BlocksLock.RLock()

	if len(n.Blocks) == 0 {
		n.BlocksLock.RUnlock()
		return EmptyBlockID
	}

	lastBlockID := n.Blocks[len(n.Blocks)-1].ID
	n.BlocksLock.RUnlock()

	return lastBlockID
}

// LastBlockIndex returns the last block index that has been finalized on this node.
func (n *Node) LastBlockIndex() uint64 {
	n.BlocksLock.RLock()

	if len(n.Blocks) == 0 {
		n.BlocksLock.RUnlock()
		return 0
	}

	lastBlockIndex := n.Blocks[len(n.Blocks)-1].Index
	n.BlocksLock.RUnlock()

	return lastBlockIndex
}

// AddTransactions adds a list of transactions into the network.
func (n *Node) AddTransactions(txs ...Transaction) {
	currentBlockIndex := n.LastBlockIndex() + 1

	n.MempoolLock.Lock()
	n.TransactionsLock.Lock()

	for _, tx := range txs {
		// Ignore transaction if it's too old
		if currentBlockIndex >= tx.Block+NumBlocksUntilPruned {
			continue
		}

		// Ignore transaction if it already exists
		if _, exists := n.Transactions[tx.ID]; exists {
			continue
		}

		item := MempoolItem{index: tx.ComputeIndex(n.LastBlockID()), id: tx.ID}

		n.Transactions[tx.ID] = tx
		n.Mempool.ReplaceOrInsert(item)
	}

	n.TransactionsLock.Unlock()
	n.MempoolLock.Unlock()
}

type QueryResponse struct {
	PeerID int
	Block  *Block
}

// ComputeStakeWeights computes the weights of blocks based on the stake of the peer which prefers it.
func (n *Node) ComputeStakeWeights(responses []*QueryResponse) map[[blake2b.Size256]byte]float64 {
	weights := make(map[[blake2b.Size256]byte]float64)

	var max float64

	for _, res := range responses {
		if res.Block == nil {
			continue
		}

		peer := n.Net.Nodes[res.PeerID]

		if peer.Stake < MinimumStake {
			weights[res.Block.ID] += MinimumStake
		} else {
			weights[res.Block.ID] += float64(peer.Stake)
		}

		if weights[res.Block.ID] > max {
			max = weights[res.Block.ID]
		}
	}

	for id := range weights {
		weights[id] /= max
	}

	return weights
}

// ComputeProfitWeights compute the weights of blocks based on the number of transactions in it.
// More transactions means more profit to the validators, hence the name.
func (n *Node) ComputeProfitWeights(responses []*QueryResponse) map[[blake2b.Size256]byte]float64 {
	weights := make(map[[blake2b.Size256]byte]float64)

	var max float64

	for _, res := range responses {
		if res.Block == nil {
			continue
		}

		weights[res.Block.ID] += float64(len(res.Block.Transactions))

		if weights[res.Block.ID] > max {
			max = weights[res.Block.ID]
		}
	}

	for id := range weights {
		weights[id] /= max
	}

	return weights
}

// FinalizeBlocks continuously attempts to finalize blocks.
func (n *Node) FinalizeBlocks() {
	for {
		n.SnowballLock.RLock()
		preferred := n.Snowball.Preferred
		last := n.Snowball.Last
		done := n.Snowball.Done
		n.SnowballLock.RUnlock()

		if preferred == nil {
			// If the node has no preferred block yet, propose a new block
			Delay(1)

			// 2^256 / 4
			maxIndex := (&big.Int{}).Exp(big.NewInt(2), big.NewInt(256), nil)
			maxIndex = maxIndex.Div(maxIndex, big.NewInt(3))

			proposing := make([][blake2b.Size256]byte, 0)

			n.MempoolLock.RLock()
			n.Mempool.AscendLessThan(MempoolItem{index: maxIndex}, func(i btree.Item) bool {
				proposing = append(proposing, i.(MempoolItem).id)
				return true
			})
			n.MempoolLock.RUnlock()

			if len(proposing) == 0 {
				continue
			}

			proposed := NewBlock(n.LastBlockIndex()+1, proposing...)

			n.SnowballLock.Lock()
			n.Snowball.Preferred = &proposed
			n.SnowballLock.Unlock()

			fmt.Printf("Node %d is proposing %d transaction(s) to be finalized into Block %d.\n", n.ID, len(proposed.Transactions), proposed.Index)

		} else {
			// If there is a preferred block, wait until snowball is done
			if !done {
				n.query()
			} else {
				n.finalize(*last)
			}
		}
	}
}

// Normalize returns a normalized weights (range [0, 1]).
func Normalize(weights map[[blake2b.Size256]byte]float64) map[[blake2b.Size256]byte]float64 {
	normalized := make(map[[blake2b.Size256]byte]float64, len(weights))
	min, max := float64(1), float64(0)

	// Find minimum weight.
	for _, weight := range weights {
		if min > weight {
			min = weight
		}
	}

	// Subtract minimum and find maximum normalized weight.
	for block, weight := range weights {
		normalized[block] = weight - min

		if normalized[block] > max {
			max = normalized[block]
		}
	}

	// Normalize weight using maximum normalized weight into range [0, 1].
	for block := range weights {
		if max == 0 {
			normalized[block] = 1
		} else {
			normalized[block] /= max
		}
	}

	return normalized
}

// query simulates a node querying K peers to decide the preferred
// block to finalize to using snowball.
func (n *Node) query() {
	currentBlockIndex := n.LastBlockIndex() + 1

	peers := n.Net.SampleNodes(n.ID)
	responses := make([]*QueryResponse, len(peers))

	var wg sync.WaitGroup
	wg.Add(len(peers))

	for i, peer := range peers {
		i, peer := i, peer

		go func() {
			Delay(1000)

			response := &QueryResponse{PeerID: peer.ID}

			if peer.LastBlockIndex()+1 == currentBlockIndex {
				// If peer is also finalizing on the same block index as the node (in sync),
				// return the peer's preferred block
				peer.SnowballLock.RLock()
				response.Block = peer.Snowball.Preferred
				peer.SnowballLock.RUnlock()

			} else if peer.LastBlockIndex()+1 > currentBlockIndex {
				// If peer is ahead of the node (currentBlockIndex has been finalized),
				// return the finalized block
				peer.BlocksLock.RLock()
				for _, block := range peer.Blocks {
					if block.Index == currentBlockIndex {
						response.Block = &block
						break
					}
				}
				peer.BlocksLock.RUnlock()

			} else {
				response.Block = nil
			}

			responses[i] = response

			wg.Done()
		}()
	}

	wg.Wait()

	// Filter away all query responses whose blocks comprise of transactions our node is not aware of.
	n.TransactionsLock.RLock()
	for _, response := range responses {
		// Filter nil block
		if response.Block == nil {
			continue
		}

		// Filter block with unexpected id
		if response.Block.Index != currentBlockIndex {
			response.Block = nil
			continue
		}

		// Filter block with at least 1 transaction not in the node's mempool
		for _, id := range response.Block.Transactions {
			if _, stored := n.Transactions[id]; !stored {
				response.Block = nil
				break
			}
		}
	}
	n.TransactionsLock.RUnlock()

	var ZeroBlockID [blake2b.Size256]byte

	// Tally up all Snowball query responses.
	tallies := make(map[[blake2b.Size256]byte]float64)
	blocks := make(map[[blake2b.Size256]byte]*Block)

	for _, response := range responses {
		if response.Block == nil {
			tallies[ZeroBlockID] += 1.0 / float64(len(responses))
			continue
		}

		if _, exists := blocks[response.Block.ID]; !exists {
			blocks[response.Block.ID] = response.Block
		}

		tallies[response.Block.ID] += 1.0 / float64(len(responses))
	}

	for block, weight := range Normalize(n.ComputeProfitWeights(responses)) {
		tallies[block] *= weight
	}

	for block, weight := range Normalize(n.ComputeStakeWeights(responses)) {
		tallies[block] *= weight
	}

	total := float64(0)

	for _, weight := range tallies {
		total += weight
	}

	for block := range tallies {
		tallies[block] /= total
	}

	// Tick Snowball with all received query responses.
	n.SnowballLock.Lock()
	n.Snowball.Tick(tallies, blocks)
	n.SnowballLock.Unlock()
}

// finalize finalizes a block after snowball beta condition has been met.
func (n *Node) finalize(newBlock Block) {
	lastBlockID := n.LastBlockID()

	n.MempoolLock.Lock()
	n.TransactionsLock.Lock()
	n.BlocksLock.Lock()
	n.SnowballLock.Lock()

	defer n.SnowballLock.Unlock()
	defer n.BlocksLock.Unlock()
	defer n.TransactionsLock.Unlock()
	defer n.MempoolLock.Unlock()

	// Append to the chain of blocks
	n.Blocks = append(n.Blocks, newBlock)

	// Delete all transactions that have been finalized from the new block.
	for _, id := range newBlock.Transactions {
		tx := n.Transactions[id]

		n.Mempool.Delete(MempoolItem{index: tx.ComputeIndex(lastBlockID)})
	}

	// Reshuffle the mempool by clearing the mempool, and repopulating it with re-indexed transactions.
	items := make([]MempoolItem, 0, n.Mempool.Len())
	n.Mempool.Ascend(func(i btree.Item) bool {
		item := i.(MempoolItem)
		tx := n.Transactions[item.id]

		// Prune away transactions older than NumBlocksUntilPruned.
		if newBlock.Index >= tx.Block+NumBlocksUntilPruned {
			delete(n.Transactions, item.id)
			return true
		}

		// Reindex transaction based on the new block id
		item.index = tx.ComputeIndex(newBlock.ID)
		items = append(items, item)

		return true
	})

	n.Mempool.Clear(false)

	// Reinsert the transactions
	for _, item := range items {
		n.Mempool.ReplaceOrInsert(item)
	}

	// Reset Snowball.
	n.Snowball.Reset()

	fmt.Printf("Node %d has finalized Block %d which contains %d transaction(s). There are %d transaction(s) in the node's mempool.\n", n.ID, newBlock.Index, len(newBlock.Transactions), len(n.Transactions))
}

// PullTransactions randomly samples at most K peers from the network,
// and request missing transactions from each of the peers.
//
// To simply the simulation however, instead of pulling missing transactions,
// it pulls all of the peer's transactions.
func (n *Node) PullTransactions() {
	for {
		Delay(1.5)

		peers := n.Net.SampleNodes(n.ID)

		pulled := make([]Transaction, 0)
		var pulledLock sync.Mutex

		var wg sync.WaitGroup
		wg.Add(len(peers))

		// Pull all transactions from sampled peers.
		for _, peer := range peers {
			go func(p *Node) {
				pulledLock.Lock()
				defer pulledLock.Unlock()

				p.MempoolLock.RLock()
				defer p.MempoolLock.RUnlock()

				// Iterate through all of the peer transactions
				for _, tx := range p.Transactions {
					pulled = append(pulled, tx)
				}

				wg.Done()
			}(peer)
		}

		wg.Wait()

		// Register all transactions we pulled into our nodes mempool and transaction index.
		n.AddTransactions(pulled...)
	}
}

// Benchmark adds transactions into the network indefinitely.
func (n *Node) Benchmark() {
	for {
		Delay(1.5)

		n.AddTransactions(n.NewTransaction())
	}
}

type Network struct {
	Nodes []*Node
}

// NewNetwork creates a simulated network with the specified number of nodes.
func NewNetwork(size int) (*Network, error) {
	net := &Network{Nodes: make([]*Node, 0, size)}

	for i := 0; i < size; i++ {
		node, err := NewNode(net, i)
		if err != nil {
			return nil, fmt.Errorf("error creating node: %w", err)
		}

		net.Nodes = append(net.Nodes, node)
	}

	for _, node := range net.Nodes {
		// Continuously benchmark the network throughout the simulation
		go node.Benchmark()

		// Run the essential goroutines
		go node.FinalizeBlocks()
		go node.PullTransactions()
	}

	return net, nil
}

// SampleNodes returns at most K randomly selected nodes from the network,
// excluding the node with the specified id.
func (n *Network) SampleNodes(skip int) []*Node {
	nodes := make([]*Node, 0, len(n.Nodes)-1)

	for _, node := range n.Nodes {
		if node.ID == skip {
			continue
		}

		nodes = append(nodes, node)
	}

	// Randomly shuffle the nodes
	rand.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	if len(nodes) > SnowballK {
		nodes = nodes[:SnowballK]
	}

	return nodes
}

// Run runs the simulation.
func Run() {
	_, err := NewNetwork(16)
	if err != nil {
		panic(err)
	}

	select {}
}
