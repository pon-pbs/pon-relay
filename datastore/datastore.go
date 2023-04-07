// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"strings"
	"sync"

	relayCommon "pon-relay.com/common"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"pon-relay.com/database"
)

type GetHeaderResponseKey struct {
	Slot           uint64
	ParentHash     string
	ProposerPubkey string
}

type GetPayloadResponseKey struct {
	Slot           uint64
	ProposerPubkey string
	BlockHash      string
}

// Datastore provides a local memory cache with a Redis and DB backend
type Datastore struct {
	log *logrus.Entry

	redis *RedisCache
	db    *database.DatabaseService

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex
}

func NewDatastore(log *logrus.Entry, redisCache *RedisCache, db *database.DatabaseService) (ds *Datastore, err error) {
	ds = &Datastore{
		log:                     log.WithField("component", "datastore"),
		db:                      db,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
	}

	return ds, err
}

// RefreshKnownValidators loads known validators from Redis into memory
func (ds *Datastore) RefreshKnownValidators() (cnt int, err error) {
	knownValidators, err := ds.redis.GetKnownValidators()
	if err != nil {
		return 0, err
	}

	knownValidatorsByIndex := make(map[uint64]types.PubkeyHex)
	for pubkey, index := range knownValidators {
		knownValidatorsByIndex[index] = pubkey
	}

	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()
	ds.knownValidatorsByPubkey = knownValidators
	ds.knownValidatorsByIndex = knownValidatorsByIndex
	return len(knownValidators), nil
}

func (ds *Datastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	_, found := ds.knownValidatorsByPubkey[pubkeyHex]
	return found
}

func (ds *Datastore) GetKnownValidatorPubkeyByIndex(index uint64) (types.PubkeyHex, bool) {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	pk, found := ds.knownValidatorsByIndex[index]
	return pk, found
}

func (ds *Datastore) NumKnownValidators() int {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	return len(ds.knownValidatorsByIndex)
}

func (ds *Datastore) NumRegisteredValidators() (uint64, error) {
	return ds.db.NumRegisteredValidators()
}

// SaveValidatorRegistration saves a validator registration into both Redis and the database
func (ds *Datastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	// First save in the database
	err := ds.db.SaveValidatorRegistration(database.SignedValidatorRegistrationToEntry(entry))
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to database")
	}

	// then save in redis
	pk := types.NewPubkeyHex(entry.Message.Pubkey.String())
	err = ds.redis.SetValidatorRegistrationTimestampIfNewer(pk, entry.Message.Timestamp)
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to redis")
	}

	return nil
}

// GetGetPayloadResponse returns the getPayload response from Redis
func (ds *Datastore) GetGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) (*types.GetPayloadResponse, error) {
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	resp, err := ds.redis.GetExecutionPayload(slot, _proposerPubkey, _blockHash)
	if err != nil {
		ds.log.WithError(err).Error("error getting getPayload response from redis")
		return resp, err
	}

	ds.log.Debug("getPayload response from redis")
	return resp, nil
}

// GetGetPayloadHeaderResponse returns the getHeader response from Redis
func (ds *Datastore) GetGetPayloadHeaderResponse(slot uint64, proposerPubkey, blockHash string) (*relayCommon.GetPayloadHeaderResponse, error) {
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	resp, err := ds.redis.GetExecutionPayloadHeader(slot, _proposerPubkey, _blockHash)
	if err != nil {
		ds.log.WithError(err).Error("error getting getPayload response from redis")
		return resp, err
	}
	ds.log.Debug("getPayload response from redis")
	return resp, nil

}
