// Package vars contains the database variables such as dynamic table names
package vars

import "pon-relay.com/common"

var (
	tableBase = common.GetEnv("DB_TABLE_PREFIX", "dev")

	TableMigrations             = tableBase + "_migrations"
	TableValidatorRegistration  = tableBase + "_validator_registration"
	TableExecutionPayload       = tableBase + "_execution_payload"
	TableBuilderBlockSubmission = tableBase + "_builder_block_submission"
	TableDeliveredPayload       = tableBase + "_payload_delivered"
	TableBlockBuilder           = tableBase + "_blockbuilder"
)
