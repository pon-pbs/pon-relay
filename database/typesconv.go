package database

import (
	"encoding/json"

	"github.com/flashbots/go-boost-utils/types"
	"pon-relay.com/common"
)

func PayloadToExecPayloadEntry(payload *types.BuilderSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	_payload, err := json.Marshal(payload.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	return &ExecutionPayloadEntry{
		Slot:           payload.Message.Slot,
		ProposerPubkey: payload.Message.ProposerPubkey.String(),
		BlockHash:      payload.ExecutionPayload.BlockHash.String(),

		Version: "bellatrix",
		Payload: string(_payload),
	}, nil
}

func BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(payload *BuilderBlockSubmissionEntry) common.BidTraceV2WithTimestampJSON {
	timestamp := payload.InsertedAt

	return common.BidTraceV2WithTimestampJSON{
		Timestamp:   timestamp.Unix(),
		TimestampMs: timestamp.UnixMilli(),
		BidTraceV2JSON: common.BidTraceV2JSON{
			Slot:           payload.Slot,
			BuilderPubkey:  payload.BuilderPubkey,
			ProposerPubkey: payload.ProposerPubkey,
			Value:          payload.Value,
		},
	}
}
