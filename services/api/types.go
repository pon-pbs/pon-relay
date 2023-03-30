package api

import (
	"errors"

	capellaAPI "github.com/attestantio/go-builder-client/api/capella"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/holiman/uint256"
	relayCommon "pon-relay.com/common"
)

var (
	ErrMissingRequest   = errors.New("req is nil")
	ErrMissingSecretKey = errors.New("secret key is nil")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var VersionBellatrix relayCommon.VersionString = "bellatrix"
var VersionCapella = consensusspec.DataVersionCapella

var ZeroU256 = types.IntToU256(0)

func BuilderSubmitBlockRequestToSignedBuilderBid(req *relayCommon.BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain types.Domain) (*capellaAPI.SignedBuilderBid, error) {
	if req == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	header := req.ExecutionPayloadHeader

	bid := new(uint256.Int)
	bid.SetFromBig(req.Message.Value.BigInt())
	builderBid := capellaAPI.BuilderBid{
		Value:  bid,
		Header: header,
		Pubkey: *pubkey,
	}

	sig, err := relayCommon.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &capellaAPI.SignedBuilderBid{
		Message:   &builderBid,
		Signature: sig,
	}, nil
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, executionPayload *types.ExecutionPayload) *types.SignedBeaconBlock {
	return &types.SignedBeaconBlock{
		Signature: signedBlindedBeaconBlock.Signature,
		Message: &types.BeaconBlock{
			Slot:          signedBlindedBeaconBlock.Message.Slot,
			ProposerIndex: signedBlindedBeaconBlock.Message.ProposerIndex,
			ParentRoot:    signedBlindedBeaconBlock.Message.ParentRoot,
			StateRoot:     signedBlindedBeaconBlock.Message.StateRoot,
			Body: &types.BeaconBlockBody{
				RandaoReveal:      signedBlindedBeaconBlock.Message.Body.RandaoReveal,
				Eth1Data:          signedBlindedBeaconBlock.Message.Body.Eth1Data,
				Graffiti:          signedBlindedBeaconBlock.Message.Body.Graffiti,
				ProposerSlashings: signedBlindedBeaconBlock.Message.Body.ProposerSlashings,
				AttesterSlashings: signedBlindedBeaconBlock.Message.Body.AttesterSlashings,
				Attestations:      signedBlindedBeaconBlock.Message.Body.Attestations,
				Deposits:          signedBlindedBeaconBlock.Message.Body.Deposits,
				VoluntaryExits:    signedBlindedBeaconBlock.Message.Body.VoluntaryExits,
				SyncAggregate:     signedBlindedBeaconBlock.Message.Body.SyncAggregate,
				ExecutionPayload:  executionPayload,
			},
		},
	}
}
