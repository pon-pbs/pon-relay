// Package database exposes the postgres database
package database

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	migrate "github.com/rubenv/sql-migrate"
	"pon-relay.com/common"
	"pon-relay.com/database/migrations"
	"pon-relay.com/database/vars"
	"pon-relay.com/ponPool"
)

type DatabaseService struct {
	DB                                    *sqlx.DB
	nstmtInsertExecutionPayload           *sqlx.NamedStmt
	nstmtInsertBlockBuilderSubmission     *sqlx.NamedStmt
	nstmtInsertGetHeaderDelivered         *sqlx.NamedStmt
	nstmtInsertBlindedBeaconBlockReporter *sqlx.NamedStmt
}

func NewDatabaseService(dsn string) (*DatabaseService, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.DB.SetMaxOpenConns(50)
	db.DB.SetMaxIdleConns(10)
	db.DB.SetConnMaxIdleTime(0)

	if os.Getenv("DB_DONT_APPLY_SCHEMA") == "" {
		migrate.SetTable(vars.TableMigrations)
		_, err := migrate.Exec(db.DB, "postgres", migrations.Migrations, migrate.Up)
		if err != nil {
			return nil, err
		}
	}

	dbService := &DatabaseService{DB: db}
	err = dbService.apiQueries()
	return dbService, err
}

func (s *DatabaseService) apiQueries() (err error) {
	query := `INSERT INTO ` + vars.TableExecutionPayload + `
	(slot, proposer_pubkey, block_hash, version, payload) VALUES
	(:slot, :proposer_pubkey, :block_hash, :version, :payload)
	ON CONFLICT (slot, proposer_pubkey, block_hash) DO UPDATE SET slot=:slot
	RETURNING id`
	s.nstmtInsertExecutionPayload, err = s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}

	query = `INSERT INTO ` + vars.TableBuilderBlockSubmission + `
	(signature, slot, builder_pubkey, proposer_pubkey, value, rpbs, epoch, transactionByteString) VALUES
	(:signature, :slot, :builder_pubkey, :proposer_pubkey, :value, :rpbs, :epoch, :transactionByteString)
	RETURNING id`
	s.nstmtInsertBlockBuilderSubmission, err = s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}

	query = `INSERT INTO ` + vars.TableDeliveredGetHeader + `
	(slot, proposer_pubkey, value) VALUES
	(:slot, :proposer_pubkey, :value)
	RETURNING id`
	s.nstmtInsertGetHeaderDelivered, err = s.DB.PrepareNamed(query)
	if err != nil {
		return err
	}
	query = `INSERT INTO ` + vars.TableBlindedBeaconBlock + `
	(signature, slot, proposer, block_hash) VALUES
	(:signature, :slot, :proposer, :block_hash)
	RETURNING id`
	s.nstmtInsertBlindedBeaconBlockReporter, err = s.DB.PrepareNamed(query)
	return err
}

func (s *DatabaseService) Close() error {
	return s.DB.Close()
}

func (s *DatabaseService) NumRegisteredValidators() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM (SELECT DISTINCT pubkey FROM ` + vars.TableValidatorRegistration + `) AS temp;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}
func (s *DatabaseService) NumBuilders() (count uint64, err error) {
	query := `SELECT COUNT(*) FROM (SELECT DISTINCT builder_pubkey FROM ` + vars.TableBlockBuilder + ` WHERE status = 1) AS temp;`
	row := s.DB.QueryRow(query)
	err = row.Scan(&count)
	return count, err
}

func (s *DatabaseService) SaveValidatorRegistration(entry ValidatorRegistrationEntry) error {
	query := `WITH latest_registration AS (
		SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature FROM ` + vars.TableValidatorRegistration + ` WHERE pubkey=:pubkey ORDER BY pubkey, timestamp DESC limit 1
	)
	INSERT INTO ` + vars.TableValidatorRegistration + ` (pubkey, fee_recipient, timestamp, gas_limit, signature)
	SELECT :pubkey, :fee_recipient, :timestamp, :gas_limit, :signature
	WHERE NOT EXISTS (
		SELECT 1 from latest_registration WHERE pubkey=:pubkey AND :timestamp <= latest_registration.timestamp OR (:fee_recipient = latest_registration.fee_recipient AND :gas_limit = latest_registration.gas_limit)
	);`
	_, err := s.DB.NamedExec(query, entry)
	return err
}

func (s *DatabaseService) GetValidatorRegistrationsForPubkeys(pubkeys []string) (entries []*ValidatorRegistrationEntry, err error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature
		FROM ` + vars.TableValidatorRegistration + `
		WHERE pubkey IN (?)
		ORDER BY pubkey, timestamp DESC;`

	q, args, err := sqlx.In(query, pubkeys)
	if err != nil {
		return nil, err
	}
	err = s.DB.Select(&entries, s.DB.Rebind(q), args...)
	return entries, err
}

func (s *DatabaseService) GetLatestValidatorRegistrations(timestampOnly bool) ([]*ValidatorRegistrationEntry, error) {
	query := `SELECT DISTINCT ON (pubkey) pubkey, fee_recipient, timestamp, gas_limit, signature`
	if timestampOnly {
		query = `SELECT DISTINCT ON (pubkey) pubkey, timestamp`
	}
	query += ` FROM ` + vars.TableValidatorRegistration + ` ORDER BY pubkey, timestamp DESC;`

	var registrations []*ValidatorRegistrationEntry
	err := s.DB.Select(&registrations, query)
	return registrations, err
}

func (s *DatabaseService) SaveBuilderBlockSubmission(payload *common.BuilderSubmitBlockRequest, RPBS *common.RpbsCommitResponse, transactionByte string) (err error) {

	rpbsJson, err := json.Marshal(RPBS)
	if err != nil {
		return err
	}

	blockSubmissionEntry := &BuilderBlockSubmissionEntry{
		Signature:             payload.Signature.String(),
		Slot:                  payload.Message.Slot,
		BuilderPubkey:         payload.Message.BuilderPubkey.String(),
		ProposerPubkey:        payload.Message.ProposerPubkey.String(),
		Value:                 payload.Message.Value.String(),
		RPBS:                  string(rpbsJson),
		Epoch:                 payload.Message.Slot / uint64(common.SlotsPerEpoch),
		TransactionByteString: transactionByte,
	}
	err = s.nstmtInsertBlockBuilderSubmission.QueryRow(blockSubmissionEntry).Scan(&blockSubmissionEntry.ID)
	return err
}

func (s *DatabaseService) SaveGetHeaderDelivered(payload *common.GetPayloadHeaderDelivered) (err error) {

	GetHeaderEntry := &GetHeaderDeliveredEntry{
		Slot:           payload.Slot,
		ProposerPubkey: payload.ProposerPubkeyHex,
		Value:          payload.Value.String(),
	}
	err = s.nstmtInsertGetHeaderDelivered.QueryRow(GetHeaderEntry).Scan(&GetHeaderEntry.ID)
	return err
}

func (s *DatabaseService) SaveBlindedBeaconBlock(payload *common.SignedBlindedBeaconBlock, proposerPublicKey string) (err error) {

	BlindedBeaconBlock := &BlindedBeaconBlockEntry{
		Signature: fmt.Sprintf("%#x", payload.Capella.Signature),
		Slot:      uint64(payload.Capella.Message.Slot),
		Proposer:  proposerPublicKey,
		BlockHash: fmt.Sprintf("%#x", payload.Capella.Message.Body.ETH1Data.BlockHash),
	}
	err = s.nstmtInsertBlindedBeaconBlockReporter.QueryRow(BlindedBeaconBlock).Scan(&BlindedBeaconBlock.ID)
	return err
}

func (s *DatabaseService) GetBlockSubmissionReporter(slotFrom uint64, slotTo uint64) (entry []*BuilderBlockSubmissionReporter, err error) {
	query := `SELECT slot, builder_pubkey, proposer_pubkey, value, rpbs, transactionbytestring
	FROM ` + vars.TableBuilderBlockSubmission + `
	WHERE slot BETWEEN $1 AND $2
	ORDER BY builder_pubkey ASC`
	entry = []*BuilderBlockSubmissionReporter{}
	err = s.DB.Select(&entry, query, slotFrom, slotTo)
	return entry, err
}

func (s *DatabaseService) GetGetHeadersDeliveredReporter(slotFrom uint64, slotTo uint64) (entry []*GetHeaderResponseReporter, err error) {
	query := `SELECT slot, proposer_pubkey, value
	FROM ` + vars.TableDeliveredGetHeader + `
	WHERE slot BETWEEN $1 AND $2`
	entry = []*GetHeaderResponseReporter{}
	err = s.DB.Select(&entry, query, slotFrom, slotTo)
	return entry, err
}

func (s *DatabaseService) GetBlindedBeaconBlockReporter(slotFrom uint64, slotTo uint64) (entry []*GetBlindedBeaconBlockReporter, err error) {
	query := `SELECT slot, signature, block_hash, proposer
	FROM ` + vars.TableBlindedBeaconBlock + `
	WHERE slot BETWEEN $1 AND $2`
	entry = []*GetBlindedBeaconBlockReporter{}
	err = s.DB.Select(&entry, query, slotFrom, slotTo)
	return entry, err
}

func (s *DatabaseService) SavePayload(bid *common.VersionedExecutionPayload, slot uint64, proposer string) error {

	payloadEntry := DeliveredPayloadEntry{

		Slot:  slot,
		Epoch: slot / uint64(common.SlotsPerEpoch),

		ProposerPubkey:       proposer,
		ProposerFeeRecipient: bid.Capella.Capella.FeeRecipient.String(),

		ParentHash:  bid.Capella.Capella.ParentHash.String(),
		BlockHash:   bid.Capella.Capella.BlockHash.String(),
		BlockNumber: bid.Capella.Capella.BlockNumber,

		GasUsed:  bid.Capella.Capella.GasUsed,
		GasLimit: bid.Capella.Capella.GasLimit,
	}

	query := `INSERT INTO ` + vars.TableDeliveredPayload + `
		(slot, epoch, proposer_pubkey, proposer_fee_recipient, parent_hash, block_hash, block_number, gas_used, gas_limit) VALUES
		(:slot, :epoch, :proposer_pubkey, :proposer_fee_recipient, :parent_hash, :block_hash, :block_number, :gas_used, :gas_limit)
		ON CONFLICT DO NOTHING`
	_, err := s.DB.NamedExec(query, payloadEntry)
	return err
}

func (s *DatabaseService) GetBlockBuilders() ([]*BlockBuilderEntry, error) {
	query := `SELECT id, inserted_at, builder_pubkey, description, is_high_prio, is_blacklisted, last_submission_id, last_submission_slot, num_submissions_total, num_submissions_simerror, num_sent_getpayload FROM ` + vars.TableBlockBuilder + ` ORDER BY id ASC;`
	entries := []*BlockBuilderEntry{}
	err := s.DB.Select(&entries, query)
	return entries, err
}

func (s *DatabaseService) SaveBuilder(entries []ponPool.Builder) error {
	query := `
	INSERT INTO ` + vars.TableBlockBuilder + ` (builder_pubkey, status)
	VALUES (:builder_pubkey, :status) ON CONFLICT (builder_pubkey) 
	DO UPDATE SET status = excluded.status`
	_, err := s.DB.NamedExec(query, entries)
	return err
}
