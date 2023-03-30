package common

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	api "github.com/attestantio/go-builder-client/api"
	capellaAPI "github.com/attestantio/go-builder-client/api/capella"
	capellaAPIV1 "github.com/attestantio/go-eth2-client/api/v1/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	capella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ssz "github.com/ferranbt/fastssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	"pon-relay.com/bls"
)

var (
	ErrLength = fmt.Errorf("incorrect byte length")
	ErrSign   = fmt.Errorf("negative value casted as unsigned int")
)
var (
	ErrUnknownNetwork = errors.New("unknown network")
	ErrEmptyPayload   = errors.New("empty payload")
)

var ZeroU256 = &uint256.Int{0}

type EcdsaSignature [65]byte

// ECDSA Functions
func (s EcdsaSignature) MarshalText() ([]byte, error) {
	return hexutil.Bytes(s[:]).MarshalText()
}

func (s *EcdsaSignature) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalJSON(input)
	if err != nil {
		return err
	}
	return s.FromSlice(b)
}

func (s *EcdsaSignature) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalText(input)
	if err != nil {
		return err
	}
	return s.FromSlice(b)
}

func (s EcdsaSignature) String() string {
	return hexutil.Bytes(s[:]).String()
}

func (s *EcdsaSignature) FromSlice(x []byte) error {
	if len(x) != 65 {
		return ErrLength
	}
	copy(s[:], x)
	return nil
}

type PubkeyHex string

type PublicKey [48]byte

func BlsPublicKeyToPublicKey(blsPubKey *bls.PublicKey) (ret phase0.BLSPubKey, err error) {
	copy(ret[:], blsPubKey.Compress())
	return ret, err
}

func (p PublicKey) MarshalText() ([]byte, error) {
	return hexutil.Bytes(p[:]).MarshalText()
}

func (p *PublicKey) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(p[:])
	if err := b.UnmarshalJSON(input); err != nil {
		return err
	}
	return p.FromSlice(b)
}

func (p *PublicKey) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(p[:])
	if err := b.UnmarshalText(input); err != nil {
		return err
	}
	return p.FromSlice(b)
}

func (p PublicKey) String() string {
	return hexutil.Bytes(p[:]).String()
}

func (p *PublicKey) FromSlice(x []byte) error {
	if len(x) != 48 {
		return ErrLength
	}
	copy(p[:], x)
	return nil
}

func HexToPubkey(s string) (ret PublicKey, err error) {
	err = ret.UnmarshalText([]byte(s))
	return ret, err
}

type (
	Hash [32]byte
	Root = Hash
)

func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

func (h *Hash) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(h[:])
	if err := b.UnmarshalJSON(input); err != nil {
		return err
	}
	return h.FromSlice(b)
}

func (h *Hash) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(h[:])
	if err := b.UnmarshalText(input); err != nil {
		return err
	}
	return h.FromSlice(b)
}

func (h *Hash) FromSlice(x []byte) error {
	if len(x) != 32 {
		return ErrLength
	}
	copy(h[:], x)
	return nil
}

func (h Hash) String() string {
	return hexutil.Bytes(h[:]).String()
}

type Signature phase0.BLSSignature

func (s Signature) MarshalText() ([]byte, error) {
	return hexutil.Bytes(s[:]).MarshalText()
}

func (s *Signature) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalJSON(input)
	if err != nil {
		return err
	}
	return s.FromSlice(b)
}

func (s *Signature) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(s[:])
	err := b.UnmarshalText(input)
	if err != nil {
		return err
	}
	return s.FromSlice(b)
}

func (s Signature) String() string {
	return hexutil.Bytes(s[:]).String()
}

func (s *Signature) FromSlice(x []byte) error {
	if len(x) != 96 {
		return ErrLength
	}
	copy(s[:], x)
	return nil
}

type BuilderBid struct {
	Header *capella.ExecutionPayloadHeader `json:"header"`
	Value  U256Str                         `json:"value" ssz-size:"32"`
	Pubkey PublicKey                       `json:"pubkey" ssz-size:"48"`
}

// MarshalSSZ ssz marshals the BuilderBid object
func (b *BuilderBid) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

func (b *BuilderBid) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(84)

	// Offset (0) 'Header'
	dst = ssz.WriteOffset(dst, offset)
	if b.Header == nil {
		b.Header = new(capella.ExecutionPayloadHeader)
	}
	offset += len(b.Header.BlockHash[:])

	// Field (1) 'Value'
	dst = append(dst, b.Value[:]...)

	// Field (2) 'Pubkey'
	dst = append(dst, b.Pubkey[:]...)

	// Field (0) 'Header'
	dst = append(dst, b.Header.BlockHash[:]...)

	return
}

type VersionedExecutionPayload struct {
	Bellatrix *boostTypes.GetPayloadResponse
	Capella   *api.VersionedExecutionPayload
}

func (e *VersionedExecutionPayload) MarshalJSON() ([]byte, error) {
	if e.Capella != nil {
		return json.Marshal(e.Capella)
	}
	if e.Bellatrix != nil {
		return json.Marshal(e.Bellatrix)
	}

	return nil, ErrEmptyPayload
}

func (e *VersionedExecutionPayload) UnmarshalJSON(data []byte) error {
	capella := new(api.VersionedExecutionPayload)
	err := json.Unmarshal(data, capella)
	if err == nil && capella.Capella != nil {
		e.Capella = capella
		return nil
	}
	bellatrix := new(boostTypes.GetPayloadResponse)
	err = json.Unmarshal(data, bellatrix)
	if err != nil {
		return err
	}
	e.Bellatrix = bellatrix
	return nil
}

type CapellaExecutionPayload struct {
	ParentHash    phase0.Hash32              `ssz-size:"32"`
	FeeRecipient  bellatrix.ExecutionAddress `ssz-size:"20"`
	StateRoot     [32]byte                   `ssz-size:"32"`
	ReceiptsRoot  [32]byte                   `ssz-size:"32"`
	LogsBloom     [256]byte                  `ssz-size:"256"`
	PrevRandao    [32]byte                   `ssz-size:"32"`
	BlockNumber   uint64
	GasLimit      uint64
	GasUsed       uint64
	Timestamp     uint64
	ExtraData     []byte                  `ssz-max:"32"`
	BaseFeePerGas [32]byte                `ssz-size:"32"`
	BlockHash     phase0.Hash32           `ssz-size:"32"`
	Transactions  []bellatrix.Transaction `ssz-max:"1048576,1073741824" ssz-size:"?,?"`
	Withdrawals   []*capella.Withdrawal   `ssz-max:"16"`
}

func (e *CapellaExecutionPayload) ExecutionPayloadToCapellaExecutionPayload() capella.ExecutionPayload {
	capellaExuctionPayload := capella.ExecutionPayload{ParentHash: e.ParentHash, FeeRecipient: e.FeeRecipient, StateRoot: e.StateRoot, ReceiptsRoot: e.ReceiptsRoot,

		LogsBloom: e.LogsBloom, PrevRandao: e.PrevRandao, BlockNumber: e.BlockNumber, GasLimit: e.GasLimit, GasUsed: e.GasUsed, Timestamp: e.Timestamp, ExtraData: e.ExtraData,
		BaseFeePerGas: e.BaseFeePerGas, BlockHash: e.BlockHash, Transactions: e.Transactions, Withdrawals: e.Withdrawals}
	return capellaExuctionPayload
}

func (b *BuilderBid) SizeSSZ() (size int) {
	size = 84

	// Field (0) 'Header'
	if b.Header == nil {
		b.Header = new(capella.ExecutionPayloadHeader)
	}
	size += len(b.Header.BlockHash[:])

	return
}

// HashTreeRoot ssz hashes the BuilderBid object
func (b *BuilderBid) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the BuilderBid object with a hasher
func (b *BuilderBid) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Header'
	hh.PutBytes(b.Header.BlockHash[:])

	// Field (1) 'Value'
	hh.PutBytes(b.Value[:])

	// Field (2) 'Pubkey'
	hh.PutBytes(b.Pubkey[:])

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the BuilderBid object
func (b *BuilderBid) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(b)
}

type SignedBuilderBid struct {
	Message   *BuilderBid `json:"message"`
	Signature Signature   `json:"signature" ssz-size:"96"`
}

type VersionString string

type GetHeaderResponse struct {
	Version consensusspec.DataVersion    `json:"version"`
	Data    *capellaAPI.SignedBuilderBid `json:"data"`
}

type BuilderSubmitBlockRequest struct {
	Signature              Signature                       `json:"signature" ssz-size:"96"`
	Message                *BidTrace                       `json:"message"`
	ExecutionPayloadHeader *capella.ExecutionPayloadHeader `json:"execution_payload_header"`
	Endpoint               string                          `json:"endpoint"`
	EcdsaSignature         EcdsaSignature                  `json:"ecdsa_signature"`
	BuilderWalletAddress   Address                         `json:"builder_wallet_address"`
	PayoutPoolTransaction  []byte                          `json:"payout_pool_transaction"`
}

type BidTrace struct {
	Slot                 uint64    `json:"slot,string"`
	ParentHash           Hash      `json:"parent_hash" ssz-size:"32"`
	BlockHash            Hash      `json:"block_hash" ssz-size:"32"`
	BuilderPubkey        PublicKey `json:"builder_pubkey" ssz-size:"48"`
	ProposerPubkey       PublicKey `json:"proposer_pubkey" ssz-size:"48"`
	ProposerFeeRecipient Address   `json:"proposer_fee_recipient" ssz-size:"20"`
	GasLimit             uint64    `json:"gas_limit,string"`
	GasUsed              uint64    `json:"gas_used,string"`
	Value                U256Str   `json:"value" ssz-size:"32"`
}

type BuilderBlockSubmissionEntry struct {
	ID         int64        `db:"id"`
	InsertedAt time.Time    `db:"inserted_at"`
	ReceivedAt sql.NullTime `db:"received_at"`

	// BidTrace data
	Signature string `db:"signature"`

	Slot       uint64 `db:"slot"`
	ParentHash string `db:"parent_hash"`
	BlockHash  string `db:"block_hash"`

	BuilderPubkey  string `db:"builder_pubkey"`
	ProposerPubkey string `db:"proposer_pubkey"`

	Value string `db:"value"`

	// Helpers
	Epoch       uint64 `db:"epoch"`
	BlockNumber uint64 `db:"block_number"`

	RPBS                  string `db:"rpbs"`
	TransactionByteString string `db:"transactionByteString"`
}

type GetPayloadResponse struct {
	Version   consensusspec.DataVersion `json:"version"`
	Bellatrix *bellatrix.ExecutionPayload
	Capella   *capella.ExecutionPayload
	API       string `json:"api"`
}

type GetPayloadHeaderResponse struct {
	Version consensusspec.DataVersion       `json:"version"`
	Data    *capella.ExecutionPayloadHeader `json:"data"`
	API     string                          `json:"api"`
}

type Address [20]byte

// Functions for Builder Wallet
func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}
func (n *U256Str) BigInt() *big.Int {
	return new(big.Int).SetBytes(reverse(n[:]))
}

func (n *U256Str) Cmp(b *U256Str) int {
	_a := n.BigInt()
	_b := b.BigInt()
	return _a.Cmp(_b)
}
func IntToU256(i uint64) (ret U256Str) {
	s := fmt.Sprint(i)
	_ = ret.UnmarshalText([]byte(s))
	return ret
}

func (a *Address) UnmarshalJSON(input []byte) error {
	b := hexutil.Bytes(a[:])
	if err := b.UnmarshalJSON(input); err != nil {
		return err
	}
	return a.FromSlice(b)
}

func (a *Address) UnmarshalText(input []byte) error {
	b := hexutil.Bytes(a[:])
	if err := b.UnmarshalText(input); err != nil {
		return err
	}
	return a.FromSlice(b)
}

func (a Address) String() string {
	return hexutil.Bytes(a[:]).String()
}

func (a *Address) FromSlice(x []byte) error {
	if len(x) != 20 {
		return ErrLength
	}
	copy(a[:], x)
	return nil
}

type SignedBlindedBeaconBlock struct {
	Bellatrix *boostTypes.SignedBlindedBeaconBlock
	Capella   *capellaAPIV1.SignedBlindedBeaconBlock
}

func (s *SignedBlindedBeaconBlock) MarshalJSON() ([]byte, error) {
	if s.Capella != nil {
		return json.Marshal(s.Capella)
	}
	if s.Bellatrix != nil {
		return json.Marshal(s.Bellatrix)
	}
	return nil, ErrEmptyPayload
}

func (s *SignedBlindedBeaconBlock) Slot() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.Slot)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Slot
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) BlockHash() string {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockHash.String()
	}
	return ""
}

func (s *SignedBlindedBeaconBlock) BlockNumber() uint64 {
	if s.Capella != nil {
		return s.Capella.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.Body.ExecutionPayloadHeader.BlockNumber
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) ProposerIndex() uint64 {
	if s.Capella != nil {
		return uint64(s.Capella.Message.ProposerIndex)
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message.ProposerIndex
	}
	return 0
}

func (s *SignedBlindedBeaconBlock) Signature() []byte {
	if s.Capella != nil {
		return s.Capella.Signature[:]
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Signature[:]
	}
	return nil
}

//nolint:nolintlint,ireturn
func (s *SignedBlindedBeaconBlock) Message() boostTypes.HashTreeRoot {
	if s.Capella != nil {
		return s.Capella.Message
	}
	if s.Bellatrix != nil {
		return s.Bellatrix.Message
	}
	return nil
}

type EthNetworkDetails struct {
	Name                     string
	GenesisForkVersionHex    string
	GenesisValidatorsRootHex string
	BellatrixForkVersionHex  string
	CapellaForkVersionHex    string

	DomainBuilder                 boostTypes.Domain
	DomainBeaconProposerBellatrix boostTypes.Domain
	DomainBeaconProposerCapella   boostTypes.Domain
}

var (
	EthNetworkKiln    = "kiln"
	EthNetworkRopsten = "ropsten"
	EthNetworkSepolia = "sepolia"
	EthNetworkGoerli  = "goerli"
	EthNetworkMainnet = "mainnet"

	CapellaForkVersionRopsten = "0x03001020"
	CapellaForkVersionSepolia = "0x90000072"
	CapellaForkVersionGoerli  = "0x03001020"
	CapellaForkVersionMainnet = "0x03000000"
)

func NewEthNetworkDetails(networkName string) (ret *EthNetworkDetails, err error) {
	var genesisForkVersion string
	var genesisValidatorsRoot string
	var bellatrixForkVersion string
	var capellaForkVersion string
	var domainBuilder boostTypes.Domain
	var domainBeaconProposerBellatrix boostTypes.Domain
	var domainBeaconProposerCapella boostTypes.Domain

	switch networkName {
	case EthNetworkSepolia:
		genesisForkVersion = GenesisForkVersionSepolia
		genesisValidatorsRoot = GenesisValidatorsRootSepolia
		bellatrixForkVersion = BellatrixForkVersionSepolia
		capellaForkVersion = CapellaForkVersionSepolia
	case EthNetworkGoerli:
		genesisForkVersion = GenesisForkVersionGoerli
		genesisValidatorsRoot = GenesisValidatorsRootGoerli
		bellatrixForkVersion = BellatrixForkVersionGoerli
		capellaForkVersion = CapellaForkVersionGoerli
	case EthNetworkMainnet:
		genesisForkVersion = GenesisForkVersionMainnet
		genesisValidatorsRoot = GenesisValidatorsRootMainnet
		bellatrixForkVersion = BellatrixForkVersionMainnet
		capellaForkVersion = CapellaForkVersionMainnet
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownNetwork, networkName)
	}

	forkV := ForkVersion{}
	forkV.FromSlice([]byte(bellatrixForkVersion))

	domainRoot := Root{}
	domainRoot.FromSlice([]byte(genesisValidatorsRoot))

	domainBuilder, err = ComputeDomain(boostTypes.DomainTypeAppBuilder, genesisForkVersion, boostTypes.Root{}.String())
	if err != nil {
		return nil, err
	}

	domainBeaconProposerBellatrix, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, bellatrixForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}
	domainBeaconProposerCapella, err = ComputeDomain(boostTypes.DomainTypeBeaconProposer, capellaForkVersion, genesisValidatorsRoot)
	if err != nil {
		return nil, err
	}

	return &EthNetworkDetails{
		Name:                          networkName,
		GenesisForkVersionHex:         genesisForkVersion,
		GenesisValidatorsRootHex:      genesisValidatorsRoot,
		BellatrixForkVersionHex:       bellatrixForkVersion,
		CapellaForkVersionHex:         capellaForkVersion,
		DomainBuilder:                 domainBuilder,
		DomainBeaconProposerBellatrix: domainBeaconProposerBellatrix,
		DomainBeaconProposerCapella:   domainBeaconProposerCapella,
	}, nil
}

type BidTraceV2 struct {
	BidTrace
	BlockNumber uint64 `json:"block_number,string" db:"block_number"`
	NumTx       uint64 `json:"num_tx,string" db:"num_tx"`
}

type BidTraceV2JSON struct {
	Slot                 uint64 `json:"slot,string"`
	ParentHash           string `json:"parent_hash"`
	BlockHash            string `json:"block_hash"`
	BuilderPubkey        string `json:"builder_pubkey"`
	ProposerPubkey       string `json:"proposer_pubkey"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
	GasLimit             uint64 `json:"gas_limit,string"`
	GasUsed              uint64 `json:"gas_used,string"`
	Value                string `json:"value"`
	NumTx                uint64 `json:"num_tx,string"`
	BlockNumber          uint64 `json:"block_number,string"`
}

func (b *BidTraceV2JSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
	}
}

func (b *BidTraceV2JSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
	}
}

type BidTraceV2WithTimestampJSON struct {
	BidTraceV2JSON
	Timestamp   int64 `json:"timestamp,string,omitempty"`
	TimestampMs int64 `json:"timestamp_ms,string,omitempty"`
}

func (b *BidTraceV2WithTimestampJSON) CSVHeader() []string {
	return []string{
		"slot",
		"parent_hash",
		"block_hash",
		"builder_pubkey",
		"proposer_pubkey",
		"proposer_fee_recipient",
		"gas_limit",
		"gas_used",
		"value",
		"num_tx",
		"block_number",
		"timestamp",
		"timestamp_ms",
	}
}

func (b *BidTraceV2WithTimestampJSON) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(b.Slot),
		b.ParentHash,
		b.BlockHash,
		b.BuilderPubkey,
		b.ProposerPubkey,
		b.ProposerFeeRecipient,
		fmt.Sprint(b.GasLimit),
		fmt.Sprint(b.GasUsed),
		b.Value,
		fmt.Sprint(b.NumTx),
		fmt.Sprint(b.BlockNumber),
		fmt.Sprint(b.Timestamp),
		fmt.Sprint(b.TimestampMs),
	}
}

type U256Str Hash // encodes/decodes to string, not hex

func reverse(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	for i := len(dst)/2 - 1; i >= 0; i-- {
		opp := len(dst) - 1 - i
		dst[i], dst[opp] = dst[opp], dst[i]
	}
	return dst
}

func (n U256Str) MarshalText() ([]byte, error) {
	return []byte(new(big.Int).SetBytes(reverse(n[:])).String()), nil
}

func (n *U256Str) UnmarshalJSON(input []byte) error {
	if len(input) < 2 {
		return ErrLength
	}
	x := new(big.Int)
	err := x.UnmarshalJSON(input[1 : len(input)-1])
	if err != nil {
		return err
	}
	return n.FromBig(x)
}

func (n *U256Str) UnmarshalText(input []byte) error {
	x := new(big.Int)
	err := x.UnmarshalText(input)
	if err != nil {
		return err
	}
	return n.FromBig(x)
}

func (n *U256Str) String() string {
	return new(big.Int).SetBytes(reverse(n[:])).String()
}

func (n *U256Str) FromSlice(x []byte) error {
	if len(x) > 32 {
		return ErrLength
	}
	copy(n[:], x)
	return nil
}

func (n *U256Str) FromBig(x *big.Int) error {
	if x.BitLen() > 256 {
		return ErrLength
	}
	if x.Sign() == -1 {
		return ErrSign
	}
	copy(n[:], reverse(x.FillBytes(n[:])))
	return nil
}

type RpbsCommitResponse map[string]string
type RpbsChallengeResponse map[string]string
type RpbsSolution map[string]string

type RpbsCommitMessage struct {
	BuilderWalletAddress *Address `json:"builderWalletAddress"`
	Slot                 uint64   `json:"slot"`
	Amount               uint64   `json:"amount"`
	TxBytes              string   `json:"txBytes"`
}

type RPBSChallenge struct {
	Commitment RpbsCommitResponse    `json:"commitment"`
	Challenge  RpbsChallengeResponse `json:"challenge"`
}
