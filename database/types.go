package database

import (
	"database/sql"
	"fmt"
	"time"
)

func NewNullInt64(i int64) sql.NullInt64 {
	return sql.NullInt64{
		Int64: i,
		Valid: true,
	}
}

func NewNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

func NewNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{
		Time:  t,
		Valid: true,
	}
}

type GetPayloadsFilters struct {
	Slot           uint64
	Cursor         uint64
	Limit          uint64
	BlockHash      string
	BlockNumber    uint64
	ProposerPubkey string
	BuilderPubkey  string
	OrderByValue   int8
}

type GetBuilderSubmissionsFilters struct {
	Slot        uint64
	Limit       uint64
	BlockHash   string
	BlockNumber uint64
	// Cursor      uint64
	BuilderPubkey string
}

type ValidatorRegistrationEntry struct {
	Pubkey string `db:"validator_pubkey"`
	Status string `db:"status"`
}

type ExecutionPayloadEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot           uint64 `db:"slot"`
	ProposerPubkey string `db:"proposer_pubkey"`
	BlockHash      string `db:"block_hash"`

	Version string `db:"version"`
	Payload string `db:"payload"`
}

var ExecutionPayloadEntryCSVHeader = []string{"id", "inserted_at", "slot", "proposer_pubkey", "block_hash", "version", "payload"}

func (e *ExecutionPayloadEntry) ToCSVRecord() []string {
	return []string{
		fmt.Sprint(e.ID),
		e.InsertedAt.UTC().String(),
		fmt.Sprint(e.Slot),
		e.ProposerPubkey,
		e.BlockHash,
		e.Version,
		e.Payload,
	}
}

type BuilderBlockSubmissionReporter struct {
	Slot           uint64 `db:"slot"`
	BuilderPubkey  string `db:"builder_pubkey"`
	ProposerPubkey string `db:"proposer_pubkey"`
	Value          string `db:"value"`
	RPBS           string `db:"rpbs"`
	Transaction    string `db:"transactionbytestring"`
}

type GetHeaderResponseReporter struct {
	Slot           uint64 `db:"slot"`
	ProposerPubkey string `db:"proposer_pubkey"`
	Value          string `db:"value"`
}

type GetBlindedBeaconBlockReporter struct {
	Slot           uint64 `db:"slot"`
	BlockHash      string `db:"block_hash"`
	Signature      string `db:"signature"`
	ProposerPubkey string `db:"proposer"`
}

type GetHeaderDeliveredEntry struct {
	ID             int64     `db:"id"`
	InsertedAt     time.Time `db:"inserted_at"`
	Slot           uint64    `db:"slot"`
	ProposerPubkey string    `db:"proposer_pubkey"`
	Value          string    `db:"value"`
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

type DeliveredPayloadEntry struct {
	ID         int64     `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot  uint64 `db:"slot"`
	Epoch uint64 `db:"epoch"`

	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	ParentHash  string `db:"parent_hash"`
	BlockHash   string `db:"block_hash"`
	BlockNumber uint64 `db:"block_number"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`
}

type BlockBuilderEntry struct {
	ID         int64     `db:"id"          json:"id"`
	InsertedAt time.Time `db:"inserted_at" json:"inserted_at"`

	BuilderPubkey string `db:"builder_pubkey" json:"builder_pubkey"`
	Description   string `db:"description"    json:"description"`

	IsHighPrio    bool `db:"is_high_prio"   json:"is_high_prio"`
	IsBlacklisted bool `db:"is_blacklisted" json:"is_blacklisted"`

	LastSubmissionID   sql.NullInt64 `db:"last_submission_id"   json:"last_submission_id"`
	LastSubmissionSlot uint64        `db:"last_submission_slot" json:"last_submission_slot"`

	NumSubmissionsTotal    uint64 `db:"num_submissions_total"    json:"num_submissions_total"`
	NumSubmissionsSimError uint64 `db:"num_submissions_simerror" json:"num_submissions_simerror"`

	NumSentGetPayload uint64 `db:"num_sent_getpayload" json:"num_sent_getpayload"`
}

type BlindedBeaconBlockEntry struct {
	ID         int64     `db:"id"          json:"id"`
	InsertedAt time.Time `db:"inserted_at" json:"inserted_at"`

	Signature string `db:"signature" json:"signature"`
	Slot      uint64 `db:"slot"    json:"slot"`

	Proposer  string `db:"proposer"   json:"proposer"`
	BlockHash string `db:"block_hash" json:"block_hash"`
}
