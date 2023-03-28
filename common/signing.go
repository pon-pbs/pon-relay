package common

import (
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/types"
	"pon-relay.com/bls"
)

type (
	Domain      [32]byte
	DomainType  [4]byte
	ForkVersion [4]byte
)

func (f *ForkVersion) FromSlice(s []byte) error {
	if len(s) != 4 {
		return errors.New("invalid fork version length")
	}
	copy(f[:], s)
	return nil
}

var (
	DomainBuilder Domain

	DomainTypeBeaconProposer = DomainType{0x00, 0x00, 0x00, 0x00}
	DomainTypeAppBuilder     = DomainType{0x00, 0x00, 0x00, 0x01}
)

type SigningData struct {
	Root   Root         `ssz-size:"32"`
	Domain types.Domain `ssz-size:"32"`
}

type ForkData struct {
	CurrentVersion        ForkVersion `ssz-size:"4"`
	GenesisValidatorsRoot Root        `ssz-size:"32"`
}

type HashTreeRoot interface {
	HashTreeRoot() ([32]byte, error)
}

func ComputeDomain(domainType types.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain types.Domain, err error) {
	genesisValidatorsRoot := types.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, ErrInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return types.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

func ComputeSigningRoot(obj HashTreeRoot, d types.Domain) ([32]byte, error) {
	var zero [32]byte
	root, err := obj.HashTreeRoot()
	if err != nil {
		return zero, err
	}
	signingData := SigningData{root, d}
	msg, err := signingData.HashTreeRoot()
	if err != nil {
		return zero, err
	}
	return msg, nil
}

func SignMessage(obj HashTreeRoot, d types.Domain, sk *bls.SecretKey) (phase0.BLSSignature, error) {
	root, err := ComputeSigningRoot(obj, d)
	if err != nil {
		return phase0.BLSSignature{}, err
	}

	signatureBytes := bls.Sign(sk, root[:]).Compress()

	var signature phase0.BLSSignature

	copy(signature[:], signatureBytes)

	return signature, nil
}

func VerifySignature(obj HashTreeRoot, d types.Domain, pkBytes, sigBytes []byte) (bool, error) {
	msg, err := ComputeSigningRoot(obj, d)
	if err != nil {
		return false, err
	}

	return bls.VerifySignatureBytes(msg[:], sigBytes, pkBytes)
}
