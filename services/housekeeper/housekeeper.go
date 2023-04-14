package housekeeper

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
	"pon-relay.com/beaconclient"
	"pon-relay.com/common"
	"pon-relay.com/database"
	"pon-relay.com/datastore"
	"pon-relay.com/ponPool"
)

var validatorActive = "2"

type HousekeeperOpts struct {
	Log          *logrus.Entry
	Redis        *datastore.RedisCache
	DB           *database.DatabaseService
	BeaconClient beaconclient.IMultiBeaconClient
	PonPool      *ponPool.PonRegistrySubgraph
}

type Housekeeper struct {
	opts *HousekeeperOpts
	log  *logrus.Entry

	redis        *datastore.RedisCache
	db           *database.DatabaseService
	beaconClient beaconclient.IMultiBeaconClient

	isStarted                uberatomic.Bool
	isUpdatingProposerDuties uberatomic.Bool
	proposerDutiesSlot       uint64

	headSlot uberatomic.Uint64

	proposersAlreadySaved map[string]bool // to avoid repeating redis writes
	validatorsLast        map[string]string

	ponPool *ponPool.PonRegistrySubgraph
}

var ErrServerAlreadyStarted = errors.New("server was already started")

func NewHousekeeper(opts *HousekeeperOpts) *Housekeeper {
	server := &Housekeeper{
		opts:                  opts,
		log:                   opts.Log,
		redis:                 opts.Redis,
		db:                    opts.DB,
		beaconClient:          opts.BeaconClient,
		proposersAlreadySaved: make(map[string]bool),
		validatorsLast:        make(map[string]string),
		ponPool:               opts.PonPool,
	}

	return server
}

// Start starts the housekeeper service, blocking
func (hk *Housekeeper) Start() (err error) {
	defer hk.isStarted.Store(false)
	if hk.isStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	// Get best beacon-node status by head slot, process current slot and start slot updates
	bestSyncStatus, err := hk.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}

	go hk.periodicTaskUpdateValidator()
	go hk.periodicTaskUpdateKnownValidators()
	go hk.periodicTaskLogValidatorsBuilders()
	go hk.periodicTaskUpdateBuilder()
	go hk.periodicTaskUpdateReporter()

	// Process the current slot
	headSlot := bestSyncStatus.HeadSlot
	hk.processNewSlot(headSlot)

	// Start regular slot updates
	c := make(chan beaconclient.HeadEventData)
	hk.beaconClient.SubscribeToHeadEvents(c)
	for {
		headEvent := <-c
		hk.processNewSlot(headEvent.Slot)
	}
}

func (hk *Housekeeper) periodicTaskLogValidatorsBuilders() {
	for {
		numRegisteredValidators, err := hk.db.NumRegisteredValidators()
		if err == nil {
			hk.log.WithField("numRegisteredValidators", numRegisteredValidators).Infof("registered validators: %d", numRegisteredValidators)
		} else {
			hk.log.WithError(err).Error("failed to get number of registered validators")
		}

		numRegisteredBuilders, err := hk.db.NumBuilders()
		if err != nil {
			hk.log.WithError(err).Error("failed to get number of active builders")
		}
		hk.log.WithField("numActiveBuilders", numRegisteredBuilders).Infof("PON builders: %d", numRegisteredBuilders)

		time.Sleep(common.DurationPerEpoch / 2)
	}
}

func (hk *Housekeeper) periodicTaskUpdateKnownValidators() {
	for {
		hk.log.Debug("periodicTaskUpdateKnownValidators start")
		hk.updateKnownValidators()
		hk.log.Debug("periodicTaskUpdateKnownValidators done")

		// Wait half an epoch
		time.Sleep(common.DurationPerEpoch / 2)
	}
}

func (hk *Housekeeper) periodicTaskUpdateBuilder() {
	for {
		hk.updateBlockBuilders()
		time.Sleep(common.DurationPerEpoch)
	}
}
func (hk *Housekeeper) periodicTaskUpdateValidator() {
	for {
		hk.updateValidatorRegistrations()
		time.Sleep(common.DurationPerEpoch)
	}
}

func (hk *Housekeeper) periodicTaskUpdateReporter() {
	for {
		hk.updateReporters()
		time.Sleep(common.DurationPerEpoch)
	}
}

func (hk *Housekeeper) processNewSlot(headSlot uint64) {
	prevHeadSlot := hk.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return
	}

	log := hk.log.WithFields(logrus.Fields{
		"headSlot":     headSlot,
		"prevHeadSlot": prevHeadSlot,
	})

	if prevHeadSlot > 0 {
		for s := prevHeadSlot + 1; s < headSlot; s++ {
			log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// Update proposer duties
	go hk.updateProposerDuties(headSlot)
	go func() {
		err := hk.redis.SetStats(datastore.RedisStatsFieldLatestSlot, headSlot)
		if err != nil {
			log.WithError(err).Error("failed to set stats")
		}
	}()

	hk.headSlot.Store(headSlot)
	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)
	log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)
}

func (hk *Housekeeper) updateKnownValidators() {
	// Query beacon node for known validators
	hk.log.Debug("Querying validators from beacon node... (this may take a while)")
	timeStartFetching := time.Now()
	validators, err := hk.beaconClient.FetchValidators(hk.headSlot.Load() - 1) // -1 to avoid "Invalid state ID: requested slot number is higher than head slot number" with multiple BNs
	if err != nil {
		hk.log.WithError(err).Error("failed to fetch validators from all beacon nodes")
		return
	}

	numValidators := len(validators)
	log := hk.log.WithField("numKnownValidators", numValidators)
	log.WithField("durationFetchValidators", time.Since(timeStartFetching).Seconds()).Infof("received validators from beacon-node")

	// Store total number of validators
	err = hk.redis.SetStats(datastore.RedisStatsFieldValidatorsTotal, fmt.Sprint(numValidators))
	if err != nil {
		log.WithError(err).Error("failed to set stats for RedisStatsFieldValidatorsTotal")
	}

	// Update Redis with validators
	log.Debug("Writing to Redis...")
	timeStartWriting := time.Now()

	printCounter := len(hk.proposersAlreadySaved) == 0 // only on first round
	i := 0
	newValidators := 0
	for _, validator := range validators {
		i++
		if printCounter && i%10000 == 0 {
			hk.log.Debugf("writing to redis: %d / %d", i, numValidators)
		}

		// avoid resaving
		if hk.proposersAlreadySaved[validator.Validator.Pubkey] {
			continue
		}

		err := hk.redis.SetKnownValidatorNX(types.PubkeyHex(validator.Validator.Pubkey), validator.Index)
		if err != nil {
			log.WithError(err).WithField("pubkey", validator.Validator.Pubkey).Error("failed to set known validator in Redis")
		} else {
			hk.proposersAlreadySaved[validator.Validator.Pubkey] = true
			newValidators++
		}
	}

	log.WithFields(logrus.Fields{
		"durationRedisWrite": time.Since(timeStartWriting).Seconds(),
		"newValidators":      newValidators,
	}).Info("updateKnownValidators done")
}

func (hk *Housekeeper) updateProposerDuties(headSlot uint64) {
	// Should only happen once at a time
	if hk.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer hk.isUpdatingProposerDuties.Store(false)

	if headSlot%uint64(common.SlotsPerEpoch/2) != 0 && headSlot-hk.proposerDutiesSlot < uint64(common.SlotsPerEpoch/2) {
		return
	}

	epoch := headSlot / uint64(common.SlotsPerEpoch)

	log := hk.log.WithFields(logrus.Fields{
		"epochFrom": epoch,
		"epochTo":   epoch + 1,
	})
	log.Debug("updating proposer duties...")

	// Query current epoch
	r, err := hk.beaconClient.GetProposerDuties(epoch)
	if err != nil {
		log.WithError(err).Error("failed to get proposer duties for all beacon nodes")
		return
	}
	entries := r.Data

	// Query next epoch
	r2, err := hk.beaconClient.GetProposerDuties(epoch + 1)
	if err != nil {
		log.WithError(err).Error("failed to get proposer duties for next epoch for all beacon nodes")
	} else if r2 != nil {
		entries = append(entries, r2.Data...)
	}

	// Get registrations from database
	pubkeys := []string{}
	for _, entry := range entries {
		pubkeys = append(pubkeys, entry.Pubkey)
	}
	validatorRegistrationEntries, err := hk.db.GetValidatorRegistrationsForPubkeys(pubkeys)
	if err != nil {
		log.WithError(err).Error("failed to get validator registrations")
		return
	}

	// Convert db entries to signed validator registration type
	PONValidators := make(map[string]string)
	for _, regEntry := range validatorRegistrationEntries {
		PONValidators[regEntry.Pubkey] = regEntry.Status
	}

	// Prepare proposer duties
	proposerDuties := []common.GetValidatorsResponseEntry{}
	for _, duty := range entries {
		reg := PONValidators[duty.Pubkey]
		if reg == validatorActive {
			proposerDuties = append(proposerDuties, common.GetValidatorsResponseEntry{
				Slot:   duty.Slot,
				PubKey: duty.Pubkey,
			})
		}
	}

	err = hk.redis.SetProposerDuties(proposerDuties)
	if err != nil {
		log.WithError(err).Error("failed to set proposer duties")
		return
	}
	hk.proposerDutiesSlot = headSlot

	// Pretty-print
	_duties := make([]string, len(proposerDuties))
	for i, duty := range proposerDuties {
		_duties[i] = fmt.Sprint(duty.Slot)
	}
	sort.Strings(_duties)
	log.WithField("numDuties", len(_duties)).Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}

func (hk *Housekeeper) updateValidatorRegistrations() {
	validators, err := hk.ponPool.GetValidators()
	if err != nil {
		hk.log.WithError(err).Error("Failed To Get Validators")
		return
	}

	hk.log.Infof("Updating %d Validators in Redis...", len(validators))
	for _, validator := range validators {
		if validator.Status == hk.validatorsLast[validator.ValidatorPubkey] {
			continue
		}
		err = hk.redis.SetValidatorStatus(validator.ValidatorPubkey, validator.Status)
		if err != nil {
			hk.log.WithError(err).Error("failed to set block builder status in redis")
		}
		hk.validatorsLast[validator.ValidatorPubkey] = validator.Status
	}
	hk.log.Infof("Updating %d Validators in Database...", len(validators))
	err = hk.db.SaveValidators(validators)
	if err != nil {
		hk.log.WithError(err).Error("failed to save block Validators")
	}
}

func (hk *Housekeeper) updateBlockBuilders() {
	builders, err := hk.ponPool.GetBuilders()
	if err != nil {
		hk.log.WithError(err).Error("Failed To Get Builders")
		return
	}

	hk.log.Infof("Updating %d block builders in Redis...", len(builders))
	for _, builder := range builders {
		err = hk.redis.SetBlockBuilderStatus(builder.BuilderPubkey, builder.Status)
		if err != nil {
			hk.log.WithError(err).Error("failed to set block builder status in redis")
		}
	}
	hk.log.Infof("Updating %d block builders in Database...", len(builders))
	err = hk.db.SaveBuilder(builders)
	if err != nil {
		hk.log.WithError(err).Error("failed to save block builders")
	}
}

func (hk *Housekeeper) updateReporters() {
	reporters, err := hk.ponPool.GetReporters()
	if err != nil {
		hk.log.WithError(err).Error("Failed To Get Reporters")
		return
	}
	hk.log.Infof("Updating %d Reporters in Database...", len(reporters))
	err = hk.db.SaveReporter(reporters)
	if err != nil {
		hk.log.WithError(err).Error("failed to save reporters")
	}
}
