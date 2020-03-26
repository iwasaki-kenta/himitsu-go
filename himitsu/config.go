package himitsu

const (
	// Snowball parameters
	SnowballK     = 3
	SnowballAlpha = 0.8
	SnowballBeta  = 150

	// NumBlocksUntilPruned is the number of blocks and transactions
	// each node will keep from the latest block index. Blocks or transactions
	// older than current block index - NumBlocksUntilPrune will be pruned.
	NumBlocksUntilPruned = 50

	// MinimumStake is the minimum amount of stake that each peer can place
	MinimumStake = 100
)
