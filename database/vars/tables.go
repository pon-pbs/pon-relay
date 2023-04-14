package vars

import "pon-relay.com/common"

var (
	tableBase                   = common.GetEnv("DB_TABLE_PREFIX", "dev")
	TableMigrations             = tableBase + "_migrations"
	TableValidators             = tableBase + "_validator_registration"
	TableExecutionPayload       = tableBase + "_execution_payload"
	TableBuilderBlockSubmission = tableBase + "_builder_block_submission"
	TableDeliveredPayload       = tableBase + "_payload_delivered"
	TableDeliveredGetHeader     = tableBase + "_get_header_delivered"
	TableBlockBuilder           = tableBase + "_blockbuilder"
	TableBlindedBeaconBlock     = tableBase + "_blinded_beacon_block"
	TableReporters              = tableBase + "_reporters"
)
