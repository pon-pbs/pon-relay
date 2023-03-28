package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/types"
	relayerCommon "pon-relay.com/common"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")
)

func SanityCheckBuilderBlockSubmission(payload *relayerCommon.BuilderSubmitBlockRequest) error {
	if payload.Message.BlockHash.String() != payload.ExecutionPayloadHeader.BlockHash.String() {
		return ErrBlockHashMismatch
	}

	if payload.Message.ParentHash.String() != payload.ExecutionPayloadHeader.ParentHash.String() {
		return ErrParentHashMismatch
	}

	return nil
}

func checkBLSPublicKeyHex(pkHex string) error {
	var proposerPubkey types.PublicKey
	return proposerPubkey.UnmarshalText([]byte(pkHex))
}
