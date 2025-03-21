package state

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/suite"
)

type AccountTestSuite struct {
	suite.Suite
}

const (
	user1      = "0x100000100000000000000000000000000000111a"
	user2      = "0x100000100000000000000000000000000000111b"
	// user1     = "0x100000100000000000000000000000000000000a"
	// user2     = "0x100000100000000000000000000000000000000d"
	ext_user1 = "0x1000001000000000000000000000000000000001"
	ext_user2 = "0x1110001000000000000000000000000000000009"
	user3     = "0x1000001000000000000000000000000000000010"
	real_user = "0xfbB9295b7Cc91219c67cd2F6f2dec9891949769b"
)

func TestAccountSuite(t *testing.T) {
	suite.Run(t, new(AccountTestSuite))
}

func (suite *AccountTestSuite) TestAccountSerialization() {
	account := &Account{
		Balance: 1000,
		Nonce:   5,
	}

	// Test serialization
	serialized := account.Serialize()
	suite.NotNil(serialized)
	suite.Greater(len(serialized), 0)

	// Test deserialization
	deserialized := Deserialize(serialized)
	suite.NotNil(deserialized)
	suite.Equal(account.Balance, deserialized.Balance)
	suite.Equal(account.Nonce, deserialized.Nonce)
}

func (suite *AccountTestSuite) TestAddressToNibbles() {
	address := common.HexToAddress("0xAbC1234567890dEf1234567890aBcDeF12345678")
	nibbles := addressToNibbles(address)

	// Check length (each byte becomes 2 nibbles)
	suite.Equal(len(address)*2, len(nibbles))

	// Check first byte conversion
	suite.Equal(address[0]>>4, nibbles[0])   // Upper nibble
	suite.Equal(address[0]&0x0F, nibbles[1]) // Lower nibble
}

func (suite *AccountTestSuite) TestAllAddressesToNibbles() {
	// Map of test addresses
	addresses := map[string]common.Address{
		"user1":     common.HexToAddress(user1),
		"user2":     common.HexToAddress(user2), 
		"ext_user1": common.HexToAddress(ext_user1),
		"ext_user2": common.HexToAddress(ext_user2),
		"user3":     common.HexToAddress(user3),
		"real_user": common.HexToAddress(real_user),
	}

	for name, addr := range addresses {
		nibbles := addressToNibbles(addr)
		
		// Check length is correct (20 bytes * 2 nibbles per byte)
		suite.Equal(40, len(nibbles), "Wrong nibble length for %s", name)

		// Reconstruct original address from nibbles to verify no data loss
		reconstructed := make([]byte, 20)
		for i := 0; i < 20; i++ {
			// Combine each pair of nibbles back into a byte
			reconstructed[i] = (nibbles[i*2] << 4) | nibbles[i*2+1]
		}

		// Compare with original address
		suite.Equal(addr.Bytes(), reconstructed, 
			"Address reconstruction failed for %s - nibbles collapsed or corrupted", name)

		// Verify each nibble is in valid range (0-15)
		for i, nib := range nibbles {
			suite.LessOrEqual(nib, byte(15), 
				"Nibble out of range for %s at position %d", name, i)
		}
	}
}

