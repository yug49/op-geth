// ShadowBase: Auto-Shield Precompile
//
// This module intercepts ETH value transfers at the EVM level and checks
// whether the recipient has auto-shield enabled in the PrivacyRouter contract.
// If enabled, the transfer is redirected to the ShieldedPool instead of the
// recipient's public balance.
//
// The PrivacyRouter's storage is read directly via StateDB (no EVM subcall),
// keeping the overhead minimal — a single SLOAD for the common PUBLIC case.

package vm

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// PrivacyRouterAddress is the system predeploy at 0x4200...0069
	PrivacyRouterAddress = common.HexToAddress("0x4200000000000000000000000000000000000069")

	// ShieldedPoolAddress is the system predeploy at 0x4200...0070
	ShieldedPoolAddress = common.HexToAddress("0x4200000000000000000000000000000000000070")

	// PrivacyBridgeAddress is the system predeploy at 0x4200...0071
	PrivacyBridgeAddress = common.HexToAddress("0x4200000000000000000000000000000000000071")

	// AutoShieldedEventTopic is keccak256("AutoShielded(address,address,uint256)")
	AutoShieldedEventTopic = crypto.Keccak256Hash([]byte("AutoShielded(address,address,uint256)"))

	// PendingShieldsBaseSlot is keccak256("shadowbase.shieldedpool.pendingShields").
	// Matches the Solidity constant _PENDING_SHIELDS_SLOT in ShieldedPool.sol.
	// Used to compute per-address storage slots for pending auto-shield balances.
	PendingShieldsBaseSlot = crypto.Keccak256Hash([]byte("shadowbase.shieldedpool.pendingShields"))

	// Solidity storage slot indices for PrivacyRouter contract:
	//   slot 0: mapping(address => PrivacyRules) _rules
	//   slot 1: mapping(address => mapping(address => bool)) _senderWhitelisted
	//   slot 2: mapping(address => mapping(address => bool)) _tokenWhitelisted
	//   slot 3: mapping(address => address[]) _senderWhitelistArray
	//   slot 4: mapping(address => address[]) _tokenWhitelistArray
	rulesSlot               = common.Hash{}                   // slot 0
	senderWhitelistedSlot   = common.BigToHash(big.NewInt(1)) // slot 1
	tokenWhitelistedSlot    = common.BigToHash(big.NewInt(2)) // slot 2
	tokenWhitelistArraySlot = common.BigToHash(big.NewInt(4)) // slot 4

	// ethTokenAddress represents native ETH (address(0)) for token whitelist checks
	ethTokenAddress = common.Address{}

	// zeroHash for empty-value comparisons
	zeroHash = common.Hash{}
)

// Privacy mode constants — mirrors the Solidity PrivacyMode enum
const (
	privacyModePublic     = 0
	privacyModeAutoShield = 1
	privacyModeCustom     = 2
)

// computeMappingSlot returns the storage slot for mapping[key] at baseSlot.
// Solidity layout: keccak256(abi.encode(key, baseSlot))
func computeMappingSlot(key common.Address, baseSlot common.Hash) common.Hash {
	padded := common.LeftPadBytes(key.Bytes(), 32)
	data := make([]byte, 64)
	copy(data[:32], padded)
	copy(data[32:], baseSlot.Bytes())
	return crypto.Keccak256Hash(data)
}

// computeNestedMappingSlot returns the storage slot for mapping[outer][inner].
// First level: keccak256(abi.encode(outer, baseSlot))
// Second level: keccak256(abi.encode(inner, firstLevel))
func computeNestedMappingSlot(outer, inner common.Address, baseSlot common.Hash) common.Hash {
	firstLevel := computeMappingSlot(outer, baseSlot)
	return computeMappingSlot(inner, firstLevel)
}

// WritePendingShield increments the pending auto-shield balance for a recipient
// in the ShieldedPool's storage. Called by the Transfer hook after redirecting
// ETH to ShieldedPool. The user later calls ShieldedPool.claimAutoShield() to
// convert this pending balance into a proper Merkle tree commitment.
//
// Storage slot: keccak256(abi.encode(recipient, keccak256("shadowbase.shieldedpool.pendingShields")))
func WritePendingShield(db StateDB, recipient common.Address, amount *big.Int) {
	slot := computeMappingSlot(recipient, PendingShieldsBaseSlot)
	current := db.GetState(ShieldedPoolAddress, slot)
	currentAmount := new(big.Int).SetBytes(current.Bytes())
	newAmount := new(big.Int).Add(currentAmount, amount)
	db.SetState(ShieldedPoolAddress, slot, common.BigToHash(newAmount))
}

// ShouldAutoShield checks whether a value transfer to `recipient` should be
// redirected to the ShieldedPool. Reads PrivacyRouter storage via StateDB.
//
// Fast path: for PUBLIC mode (default for all addresses), this performs a
// single storage read and returns false. Zero overhead for non-private users.
func ShouldAutoShield(db StateDB, recipient, sender common.Address, amount *big.Int) bool {
	// --- Edge cases (no storage reads) ---

	// Zero-value transfers: never shield
	if amount == nil || amount.Sign() <= 0 {
		return false
	}

	// Self-transfers: never shield
	if recipient == sender {
		return false
	}

	// System predeploys: never shield transfers to the privacy system itself
	if recipient == PrivacyRouterAddress || recipient == ShieldedPoolAddress || recipient == PrivacyBridgeAddress {
		return false
	}

	// PrivacyRouter must be deployed (has code)
	if db.GetCodeSize(PrivacyRouterAddress) == 0 {
		return false
	}

	// --- Read recipient's privacy mode (1 SLOAD — the common-case cost) ---

	rulesBaseSlot := computeMappingSlot(recipient, rulesSlot)
	modeRaw := db.GetState(PrivacyRouterAddress, rulesBaseSlot)

	// Fast path: PUBLIC (0) is the default — storage returns zero
	if modeRaw == zeroHash {
		return false
	}

	mode := new(big.Int).SetBytes(modeRaw.Bytes()).Uint64()
	if mode == privacyModePublic {
		return false
	}

	// --- AUTO_SHIELD or CUSTOM: evaluate detailed rules ---

	// Sender whitelist: _senderWhitelisted[recipient][sender]
	senderWlSlot := computeNestedMappingSlot(recipient, sender, senderWhitelistedSlot)
	if db.GetState(PrivacyRouterAddress, senderWlSlot) != zeroHash {
		return false // sender whitelisted → keep transfer public
	}

	// Minimum amount: _rules[recipient].minAmount (baseSlot + 1)
	minAmountSlot := common.BigToHash(new(big.Int).Add(
		new(big.Int).SetBytes(rulesBaseSlot.Bytes()), big.NewInt(1),
	))
	minAmountRaw := db.GetState(PrivacyRouterAddress, minAmountSlot)
	if minAmountRaw != zeroHash {
		minAmount := new(big.Int).SetBytes(minAmountRaw.Bytes())
		if amount.Cmp(minAmount) < 0 {
			return false // below minimum threshold
		}
	}

	// Token whitelist (for native ETH, token = address(0))
	// Only check if the whitelist is non-empty
	tokenWlLenSlot := computeMappingSlot(recipient, tokenWhitelistArraySlot)
	tokenWlLen := db.GetState(PrivacyRouterAddress, tokenWlLenSlot)
	if tokenWlLen != zeroHash {
		// Whitelist is non-empty — ETH must be explicitly listed
		tokenWlSlot := computeNestedMappingSlot(recipient, ethTokenAddress, tokenWhitelistedSlot)
		if db.GetState(PrivacyRouterAddress, tokenWlSlot) == zeroHash {
			return false // ETH not in token whitelist
		}
	}

	// All checks passed → auto-shield this transfer
	return true
}

// --- Precompile registration ---

// AutoShieldPrecompile is registered in the EVM precompile registry at address 0x42.
// It serves as the on-chain entry point for the auto-shield system.
// The actual transfer interception runs in the Transfer hook (core/evm.go) which
// has full StateDB access; this precompile is registered for address reservation
// and can be called to confirm auto-shield is active.
type AutoShieldPrecompile struct{}

func (a *AutoShieldPrecompile) RequiredGas(input []byte) uint64 {
	return 100 // minimal gas
}

func (a *AutoShieldPrecompile) Run(input []byte) ([]byte, error) {
	// Return 0x01 (true) to indicate auto-shield is active on this chain.
	// The actual shouldShield evaluation happens in the Transfer hook with
	// full StateDB access — this precompile confirms capability only.
	return common.LeftPadBytes([]byte{1}, 32), nil
}

// --- Transaction-level rewriting helpers ---

// RouteShieldSelector is the 4-byte selector for routeShield(address).
// keccak256("routeShield(address)")[:4]
var RouteShieldSelector = crypto.Keccak256([]byte("routeShield(address)"))[:4]

// EncodeRouteShieldCalldata builds calldata for PrivacyRouter.routeShield(recipient).
// Format: selector (4 bytes) + abi-encoded address (32 bytes, left-padded).
func EncodeRouteShieldCalldata(recipient common.Address) []byte {
	data := make([]byte, 36)
	copy(data[:4], RouteShieldSelector)
	copy(data[4+12:], recipient.Bytes()) // left-pad 20-byte address to 32 bytes
	return data
}

// IsRouteShieldCall checks if calldata is a routeShield(address) call.
func IsRouteShieldCall(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == RouteShieldSelector[0] &&
		data[1] == RouteShieldSelector[1] &&
		data[2] == RouteShieldSelector[2] &&
		data[3] == RouteShieldSelector[3]
}
