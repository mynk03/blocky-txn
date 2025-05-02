package chain

import "blockchain-simulator/internal/blockchain"

var chain blockchain.Blockchain

func SetChainInstance(chainInstance blockchain.Blockchain){
	chain = chainInstance
}

func GetChainInstance() blockchain.Blockchain {
	return chain 
} 
