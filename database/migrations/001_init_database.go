package migrations

import (
	migrate "github.com/rubenv/sql-migrate"
	"pon-relay.com/database/vars"
)

var Migration001InitDatabase = &migrate.Migration{
	Id: "001-init-database",
	Up: []string{`
		CREATE TABLE IF NOT EXISTS ` + vars.TableValidatorRegistration + ` (
			id          bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
			inserted_at timestamp NOT NULL default current_timestamp,

			pubkey        varchar(98) NOT NULL,
			fee_recipient varchar(42) NOT NULL,
			timestamp     bigint NOT NULL,
			gas_limit     bigint NOT NULL,
			signature     text NOT NULL
		);

		CREATE UNIQUE INDEX IF NOT EXISTS ` + vars.TableValidatorRegistration + `_pubkey_timestamp_uidx ON ` + vars.TableValidatorRegistration + `(pubkey, timestamp DESC);


		CREATE TABLE IF NOT EXISTS ` + vars.TableExecutionPayload + ` (
			id          bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
			inserted_at timestamp NOT NULL default current_timestamp,

			slot            bigint NOT NULL,
			proposer_pubkey varchar(98) NOT NULL,
			block_hash      varchar(66) NOT NULL,

			version     text NOT NULL, -- bellatrix
			payload 	json NOT NULL
		);

		CREATE UNIQUE INDEX IF NOT EXISTS ` + vars.TableExecutionPayload + `_slot_pk_hash_idx ON ` + vars.TableExecutionPayload + `(slot, proposer_pubkey, block_hash);

		DROP TABLE IF EXISTS ` + vars.TableBuilderBlockSubmission + `;
		CREATE TABLE IF NOT EXISTS ` + vars.TableBuilderBlockSubmission + ` (
			id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
			inserted_at timestamp NOT NULL default current_timestamp,
			signature            text NOT NULL,
			rpbs				 text NOT NULL,
			transactionByteString text NOT NULL,
			slot        bigint NOT NULL,
			builder_pubkey         varchar(98) NOT NULL,
			proposer_pubkey        varchar(98) NOT NULL,
			value  NUMERIC(48, 0),
			-- helpers
			epoch        bigint NOT NULL
		);

		CREATE INDEX IF NOT EXISTS ` + vars.TableBuilderBlockSubmission + `_slot_idx ON ` + vars.TableBuilderBlockSubmission + `("slot");
		CREATE INDEX IF NOT EXISTS ` + vars.TableBuilderBlockSubmission + `_builderpubkey_idx ON ` + vars.TableBuilderBlockSubmission + `("builder_pubkey");


		CREATE TABLE IF NOT EXISTS ` + vars.TableDeliveredPayload + ` (
			id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
			inserted_at timestamp NOT NULL default current_timestamp,

			signed_blinded_beacon_block json,

			epoch bigint NOT NULL,
			slot  bigint NOT NULL,

			builder_pubkey         varchar(98) NOT NULL,
			proposer_pubkey        varchar(98) NOT NULL,
			proposer_fee_recipient varchar(42) NOT NULL,

			parent_hash  varchar(66) NOT NULL,
			block_hash   varchar(66) NOT NULL,
			block_number bigint NOT NULL,

			gas_used  bigint NOT NULL,
			gas_limit bigint NOT NULL,

			value   NUMERIC(48, 0),

			UNIQUE (slot, proposer_pubkey, block_hash)
		);

		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_slot_idx ON ` + vars.TableDeliveredPayload + `("slot");
		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_blockhash_idx ON ` + vars.TableDeliveredPayload + `("block_hash");
		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_blocknumber_idx ON ` + vars.TableDeliveredPayload + `("block_number");
		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_proposerpubkey_idx ON ` + vars.TableDeliveredPayload + `("proposer_pubkey");
		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_builderpubkey_idx ON ` + vars.TableDeliveredPayload + `("builder_pubkey");
		CREATE INDEX IF NOT EXISTS ` + vars.TableDeliveredPayload + `_value_idx ON ` + vars.TableDeliveredPayload + `("value");


		CREATE TABLE IF NOT EXISTS ` + vars.TableBlockBuilder + ` (
			id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
			inserted_at timestamp NOT NULL default current_timestamp,

			builder_pubkey  varchar(98) NOT NULL,
			description    	text NOT NULL,

			is_high_prio    boolean NOT NULL,
			is_blacklisted  boolean NOT NULL,

			last_submission_id   bigint references ` + vars.TableBuilderBlockSubmission + `(id) on delete set null,
			last_submission_slot bigint NOT NULL,

			num_submissions_total    bigint NOT NULL,
			num_submissions_simerror bigint NOT NULL,
			num_submissions_topbid   bigint NOT NULL,

			num_sent_getpayload bigint NOT NULL DEFAULT 0,

			UNIQUE (builder_pubkey)
		);
		`},
	Down: []string{`
		DROP TABLE IF EXISTS ` + vars.TableBuilderBlockSubmission + `;
		DROP TABLE IF EXISTS ` + vars.TableDeliveredPayload + `;
		DROP TABLE IF EXISTS ` + vars.TableBlockBuilder + `;
		DROP TABLE IF EXISTS ` + vars.TableExecutionPayload + `;
		DROP TABLE IF EXISTS ` + vars.TableValidatorRegistration + `;
		`},
	DisableTransactionUp:   false,
	DisableTransactionDown: false,
}
