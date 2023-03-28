// Package api contains the API webserver for the proposer and block-builder APIs
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NYTimes/gziphandler"
	capellaAPISpec "github.com/attestantio/go-builder-client/api"
	capellaAPI "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/go-redis/redis/v9"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	blst "github.com/supranational/blst/bindings/go"
	uberatomic "go.uber.org/atomic"
	"pon-relay.com/beaconclient"
	"pon-relay.com/bls"
	"pon-relay.com/common"
	"pon-relay.com/database"
	"pon-relay.com/datastore"
)

var (
	ErrMissingLogOpt              = errors.New("log parameter is nil")
	ErrMissingBeaconClientOpt     = errors.New("beacon-client is nil")
	ErrMissingDatastoreOpt        = errors.New("proposer datastore is nil")
	ErrRelayPubkeyMismatch        = errors.New("relay pubkey does not match existing one")
	ErrServerAlreadyStarted       = errors.New("server was already started")
	ErrBuilderAPIWithoutSecretKey = errors.New("cannot start builder API without secret key")
)

var (
	rpbsServer = cli.GetEnv("RPBS_SERVER_URL", "http://localhost:3000")
)

var (
	// Proposer API (builder-specs)
	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"
	pathGetTestPayload    = "/eth/v1/builder/blinded_block"

	// Block builder API
	pathBuilderGetValidators = "/relay/v1/builder/validators"
	pathSubmitNewBlock       = "/relay/v1/builder/blocks"
	// Data API
	pathDataProposerPayloadDelivered = "/relay/v1/data/bidtraces/proposer_payload_delivered"
	pathDataBuilderBidsReceived      = "/relay/v1/data/bidtraces/builder_blocks_received"
	pathDataValidatorRegistration    = "/relay/v1/data/validator_registration"

	// Internal API
	pathInternalBuilderStatus = "/internal/v1/builder/{pubkey:0x[a-fA-F0-9]+}"

	// number of goroutines to save active validator
	numActiveValidatorProcessors = cli.GetEnvInt("NUM_ACTIVE_VALIDATOR_PROCESSORS", 10)
	numValidatorRegProcessors    = cli.GetEnvInt("NUM_VALIDATOR_REG_PROCESSORS", 10)
	timeoutGetPayloadRetryMs     = cli.GetEnvInt("GETPAYLOAD_RETRY_TIMEOUT_MS", 100)

	apiReadTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_READ_MS", 1500)
	apiReadHeaderTimeoutMs = cli.GetEnvInt("API_TIMEOUT_READHEADER_MS", 600)
	apiWriteTimeoutMs      = cli.GetEnvInt("API_TIMEOUT_WRITE_MS", 10000)
	apiIdleTimeoutMs       = cli.GetEnvInt("API_TIMEOUT_IDLE_MS", 3000)

	// RPBS Endpoint
	pathPublicKey = "/relay/v1/rpbs/public_key"
)

// RelayAPIOpts contains the options for a relay
type RelayAPIOpts struct {
	Log *logrus.Entry

	ListenAddr string

	BeaconClient beaconclient.IMultiBeaconClient
	Datastore    *datastore.Datastore
	Redis        *datastore.RedisCache
	DB           *database.DatabaseService

	SecretKey *bls.SecretKey // used to sign bids (getHeader responses)

	// Network specific variables
	EthNetDetails common.EthNetworkDetails

	// APIs to enable
	ProposerAPI     bool
	BlockBuilderAPI bool
	DataAPI         bool
	PprofAPI        bool
	InternalAPI     bool
	RPBSAPI         bool
}

type randaoHelper struct {
	slot       uint64
	prevRandao string
}

// RelayAPI represents a single Relay instance
type RelayAPI struct {
	opts RelayAPIOpts
	log  *logrus.Entry

	blsSk     *bls.SecretKey
	publicKey *phase0.BLSPubKey
	client    *http.Client

	srv        *http.Server
	srvStarted uberatomic.Bool

	beaconClient beaconclient.IMultiBeaconClient
	datastore    *datastore.Datastore
	redis        *datastore.RedisCache
	db           *database.DatabaseService

	headSlot    uberatomic.Uint64
	genesisInfo *beaconclient.GetGenesisResponse

	proposerDutiesLock       sync.RWMutex
	proposerDutiesResponse   []types.BuilderGetValidatorsResponseEntry
	proposerDutiesMap        map[uint64]*types.RegisterValidatorRequestMessage
	proposerDutiesSlot       uint64
	isUpdatingProposerDuties uberatomic.Bool

	activeValidatorC chan types.PubkeyHex
	validatorRegC    chan types.SignedValidatorRegistration

	// used to wait on any active getPayload calls on shutdown
	getPayloadCallsInFlight sync.WaitGroup

	// Feature flags
	ffForceGetHeader204      bool
	ffDisableBlockPublishing bool
	ffDisableLowPrioBuilders bool

	expectedPrevRandao         randaoHelper
	expectedPrevRandaoLock     sync.RWMutex
	expectedPrevRandaoUpdating uint64
	RPBS                       *common.RPBSService
}

// NewRelayAPI creates a new service. if builders is nil, allow any builder
func NewRelayAPI(opts RelayAPIOpts) (api *RelayAPI, err error) {
	if opts.Log == nil {
		return nil, ErrMissingLogOpt
	}

	if opts.BeaconClient == nil {
		return nil, ErrMissingBeaconClientOpt
	}

	if opts.Datastore == nil {
		return nil, ErrMissingDatastoreOpt
	}

	// If block-builder API is enabled, then ensure secret key is all set
	var publicKey phase0.BLSPubKey
	if opts.BlockBuilderAPI {
		if opts.SecretKey == nil {
			return nil, ErrBuilderAPIWithoutSecretKey
		}

		// If using a secret key, ensure it's the correct one
		publicKey, err = common.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(opts.SecretKey))
		if err != nil {
			return nil, err
		}
		opts.Log.Infof("Using BLS key: %s", publicKey.String())

		// ensure pubkey is same across all relay instances
		_pubkey, err := opts.Redis.GetRelayConfig(datastore.RedisConfigFieldPubkey)
		if err != nil {
			return nil, err
		} else if _pubkey == "" {
			err := opts.Redis.SetRelayConfig(datastore.RedisConfigFieldPubkey, publicKey.String())
			if err != nil {
				return nil, err
			}
		} else if _pubkey != publicKey.String() {
			return nil, fmt.Errorf("%w: new=%s old=%s", ErrRelayPubkeyMismatch, publicKey.String(), _pubkey)
		}
	}

	api = &RelayAPI{
		opts:                   opts,
		log:                    opts.Log,
		blsSk:                  opts.SecretKey,
		publicKey:              &publicKey,
		datastore:              opts.Datastore,
		beaconClient:           opts.BeaconClient,
		redis:                  opts.Redis,
		db:                     opts.DB,
		proposerDutiesResponse: []types.BuilderGetValidatorsResponseEntry{},
		client:                 &http.Client{},
		RPBS:                   common.NewRPBSService(rpbsServer, " "),

		activeValidatorC: make(chan types.PubkeyHex, 450_000),
		validatorRegC:    make(chan types.SignedValidatorRegistration, 450_000),
	}

	if os.Getenv("FORCE_GET_HEADER_204") == "1" {
		api.log.Warn("env: FORCE_GET_HEADER_204 - forcing getHeader to always return 204")
		api.ffForceGetHeader204 = true
	}

	if os.Getenv("DISABLE_BLOCK_PUBLISHING") == "1" {
		api.log.Warn("env: DISABLE_BLOCK_PUBLISHING - disabling publishing blocks on getPayload")
		api.ffDisableBlockPublishing = true
	}

	if os.Getenv("DISABLE_LOWPRIO_BUILDERS") == "1" {
		api.log.Warn("env: DISABLE_LOWPRIO_BUILDERS - allowing only high-level builders")
		api.ffDisableLowPrioBuilders = true
	}

	return api, nil
}

func (api *RelayAPI) getRouter() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/", api.handleRoot).Methods(http.MethodGet)

	// Proposer API
	if api.opts.ProposerAPI {
		api.log.Info("proposer API enabled")
		r.HandleFunc(pathStatus, api.handleStatus).Methods(http.MethodGet)
		r.HandleFunc(pathGetHeader, api.handleGetHeader).Methods(http.MethodGet)
		r.HandleFunc(pathGetPayload, api.handleGetPayload).Methods(http.MethodPost)
		r.HandleFunc(pathGetTestPayload, api.handleGetTestPayload).Methods(http.MethodPost)
		r.HandleFunc(pathRegisterValidator, api.handleRegisterValidator).Methods(http.MethodPost)
	}

	// Builder API
	if api.opts.BlockBuilderAPI {
		api.log.Info("block builder API enabled")
		r.HandleFunc(pathSubmitNewBlock, api.handleSubmitNewBlock).Methods(http.MethodPost)
	}

	// Pprof
	if api.opts.PprofAPI {
		api.log.Info("pprof API enabled")
		r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	}

	if api.opts.RPBSAPI {
		api.log.Info("RPBS enabled")
		r.HandleFunc(pathPublicKey, api.handlePublicKey).Methods(http.MethodGet)
	}

	// r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(api.log, r)
	withGz := gziphandler.GzipHandler(loggedRouter)
	return withGz
}

// StartServer starts the HTTP server for this instance
func (api *RelayAPI) StartServer() (err error) {
	if api.srvStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	// Get best beacon-node status by head slot, process current slot and start slot updates
	bestSyncStatus, err := api.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}

	api.genesisInfo, err = api.beaconClient.GetGenesis()
	if err != nil {
		return err
	}
	api.log.Infof("genesis info: %d", api.genesisInfo.Data.GenesisTime)

	// start things for the block-builder API
	if api.opts.BlockBuilderAPI {
		// Get current proposer duties blocking before starting, to have them ready
		api.updateProposerDuties(bestSyncStatus.HeadSlot)
	}

	// start things specific for the proposer API
	if api.opts.ProposerAPI {
		// Update list of known validators, and start refresh loop
		go api.startKnownValidatorUpdates()

		// Start the worker pool to process active validators
		api.log.Infof("starting %d active validator processors", numActiveValidatorProcessors)
		for i := 0; i < numActiveValidatorProcessors; i++ {
			go api.startActiveValidatorProcessor()
		}

		// Start the validator registration db-save processor
		api.log.Infof("starting %d validator registration processors", numValidatorRegProcessors)
		for i := 0; i < numValidatorRegProcessors; i++ {
			go api.startValidatorRegistrationDBProcessor()
		}
	}

	// Process current slot
	api.processNewSlot(bestSyncStatus.HeadSlot)

	// Start regular slot updates
	go func() {
		c := make(chan beaconclient.HeadEventData)
		api.beaconClient.SubscribeToHeadEvents(c)
		for {
			headEvent := <-c
			api.processNewSlot(headEvent.Slot)
		}
	}()

	api.srv = &http.Server{
		Addr:    api.opts.ListenAddr,
		Handler: api.getRouter(),

		ReadTimeout:       time.Duration(apiReadTimeoutMs) * time.Millisecond,
		ReadHeaderTimeout: time.Duration(apiReadHeaderTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(apiWriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       time.Duration(apiIdleTimeoutMs) * time.Millisecond,
	}

	err = api.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// StopServer disables sending any bids on getHeader calls, waits a few seconds to catch any remaining getPayload call, and then shuts down the webserver
func (api *RelayAPI) StopServer() (err error) {
	api.log.Info("Stopping server...")

	if api.opts.ProposerAPI {
		// stop sending bids
		api.ffForceGetHeader204 = true
		api.log.Info("Disabled sending bids, waiting a few seconds...")

		// wait a few seconds, for any pending getPayload call to complete
		time.Sleep(5 * time.Second)

		// wait for any active getPayload call to finish
		api.getPayloadCallsInFlight.Wait()
	}

	// shutdown
	return api.srv.Shutdown(context.Background())
}

// startActiveValidatorProcessor keeps listening on the channel and saving active validators to redis
func (api *RelayAPI) startActiveValidatorProcessor() {
	for pubkey := range api.activeValidatorC {
		err := api.redis.SetActiveValidator(pubkey)
		if err != nil {
			api.log.WithError(err).Infof("error setting active validator")
		}
	}
}

// startActiveValidatorProcessor keeps listening on the channel and saving active validators to redis
func (api *RelayAPI) startValidatorRegistrationDBProcessor() {
	for valReg := range api.validatorRegC {
		err := api.datastore.SaveValidatorRegistration(valReg)
		if err != nil {
			api.log.WithError(err).WithFields(logrus.Fields{
				"reg_pubkey":       valReg.Message.Pubkey,
				"reg_feeRecipient": valReg.Message.FeeRecipient,
				"reg_gasLimit":     valReg.Message.GasLimit,
				"reg_timestamp":    valReg.Message.Timestamp,
			}).Error("error saving validator registration")
		}
	}
}

func (api *RelayAPI) processNewSlot(headSlot uint64) {
	_apiHeadSlot := api.headSlot.Load()
	if headSlot <= _apiHeadSlot {
		return
	}

	if _apiHeadSlot > 0 {
		for s := _apiHeadSlot + 1; s < headSlot; s++ {
			api.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// store the head slot
	api.headSlot.Store(headSlot)

	// only for builder-api
	if api.opts.BlockBuilderAPI {
		// query the expected prev_randao field
		go api.updatedExpectedRandao(headSlot)

		// update proposer duties in the background
		go api.updateProposerDuties(headSlot)
	}

	// log
	epoch := headSlot / uint64(common.SlotsPerEpoch)
	api.log.WithFields(logrus.Fields{
		"epoch":              epoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (epoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)
}

func (api *RelayAPI) updateProposerDuties(headSlot uint64) {
	// Ensure only one updating is running at a time
	if api.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer api.isUpdatingProposerDuties.Store(false)

	// Update once every 8 slots (or more, if a slot was missed)
	if headSlot%8 != 0 && headSlot-api.proposerDutiesSlot < 8 {
		return
	}

	// Get duties from mem
	duties, err := api.redis.GetProposerDuties()
	dutiesMap := make(map[uint64]*types.RegisterValidatorRequestMessage)
	for _, duty := range duties {
		dutiesMap[duty.Slot] = duty.Entry.Message
	}

	if err == nil {
		api.proposerDutiesLock.Lock()
		api.proposerDutiesResponse = duties
		api.proposerDutiesMap = dutiesMap
		api.proposerDutiesSlot = headSlot
		api.proposerDutiesLock.Unlock()

		// pretty-print
		_duties := make([]string, len(duties))
		for i, duty := range duties {
			_duties[i] = fmt.Sprint(duty.Slot)
		}
		sort.Strings(_duties)
		api.log.Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
	} else {
		api.log.WithError(err).Error("failed to update proposer duties")
	}
}

func (api *RelayAPI) startKnownValidatorUpdates() {
	for {
		// Refresh known validators
		cnt, err := api.datastore.RefreshKnownValidators()
		if err != nil {
			api.log.WithError(err).Error("error getting known validators")
		} else {
			api.log.WithField("cnt", cnt).Info("updated known validators")
		}

		// Wait for one epoch (at the beginning, because initially the validators have already been queried)
		time.Sleep(common.DurationPerEpoch / 2)
	}
}

func (api *RelayAPI) RespondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := HTTPErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		api.log.WithField("response", resp).WithError(err).Error("Couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) RespondOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		api.log.WithField("response", response).WithError(err).Error("Couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (api *RelayAPI) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// ---------------
//  PROPOSER APIS
// ---------------

func (api *RelayAPI) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "PON Relay API")
}

func (api *RelayAPI) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slotStr := vars["slot"]
	parentHashHex := vars["parent_hash"]
	proposerPubkeyHex := vars["pubkey"]
	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slotStr,
		"parentHash": parentHashHex,
		"pubkey":     proposerPubkeyHex,
		"ua":         ua,
		"mevBoostV":  common.GetMevBoostVersionFromUserAgent(ua),
	})

	slot, err := strconv.ParseUint(slotStr, 10, 64)
	if err != nil {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidSlot.Error())
		return
	}

	if len(proposerPubkeyHex) != 98 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		api.RespondError(w, http.StatusBadRequest, common.ErrInvalidHash.Error())
		return
	}

	log.Debug("getHeader request received")

	bid, err := api.redis.GetBestBid(slot, parentHashHex, proposerPubkeyHex)
	if err != nil {
		log.WithError(err).Error("could not get bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if bid == nil || bid.Data == nil || bid.Data.Message == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Error on bid without value
	if bid.Data.Message.Value.Cmp(common.ZeroU256) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	log.WithFields(logrus.Fields{
		"value":     bid.Data.Message.Value.String(),
		"blockHash": bid.Data.Message.Header.BlockHash.String(),
	}).Info("bid delivered")
	api.RespondOK(w, bid)
}

type (
	PublicKey     = blst.P1Affine
	SecretKey     = blst.SecretKey
	BLSTSignature = blst.P2Affine
)

func (api *RelayAPI) handleGetTestPayload(w http.ResponseWriter, req *http.Request) {
	api.getPayloadCallsInFlight.Add(1)
	defer api.getPayloadCallsInFlight.Done()

	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":        "getPayload",
		"ua":            ua,
		"mevBoostV":     common.GetMevBoostVersionFromUserAgent(ua),
		"contentLength": req.ContentLength,
	})

	payload := new(common.SignedBlindedBeaconBlock)
	capellaPayload := new(capellaAPI.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(capellaPayload); err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.WithError(err).Error("getPayload request failed to decode (i/o timeout)")
		} else {
			log.WithError(err).Warn("getPayload request failed to decode")
		}
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload.Capella = capellaPayload

	slot := payload.Slot()
	log = log.WithFields(logrus.Fields{
		"slot":      slot,
		"blockHash": payload.BlockHash(),
		"idArg":     req.URL.Query().Get("id"),
	})

	log.Debug("getPayload request received")

	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.ProposerIndex())
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", payload.ProposerIndex())
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	log = log.WithField("pubkeyFromIndex", proposerPubkey)

	pk, err := types.HexToPubkey(proposerPubkey.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	ok, err := types.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBeaconProposerCapella, pk[:], payload.Signature())
	if !ok || err != nil {
		fmt.Println("Signature Failed")
	}
	fmt.Println("Signature Verified")
	blockHash := payload.BlockHash()
	blockSubmission, err := api.datastore.GetGetPayloadHeaderResponse(slot, proposerPubkey.String(), blockHash)
	if err != nil || blockSubmission == nil {
		log.WithError(err).Warn("failed getting execution payload (1/2)")
		time.Sleep(time.Duration(timeoutGetPayloadRetryMs) * time.Millisecond)

		// Try again
		blockSubmission, err = api.datastore.GetGetPayloadHeaderResponse(slot, proposerPubkey.String(), blockHash)
		if err != nil {
			log.WithError(err).Error("failed getting execution payload (2/2) - due to error")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		} else if blockSubmission == nil {
			log.Warn("failed getting execution payload (2/2)")
			api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
			return
		}
	}
	fmt.Println(blockSubmission.API)

	postBody, _ := json.Marshal(payload.Capella)
	capella_json := new(capellaAPI.SignedBlindedBeaconBlock)
	json.NewDecoder(bytes.NewReader(postBody)).Decode(capella_json)

	resp, err := http.Post(blockSubmission.API, "application/json", bytes.NewReader(postBody))
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
		return
	}
	defer resp.Body.Close()

	// Check is the response is 200
	if resp.StatusCode != http.StatusOK {
		log.WithError(err).Error("getPayload request failed")
		response, _ := io.ReadAll(resp.Body)
		fmt.Println(string(response))
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	getPayloadResponse := new(common.CapellaExecutionPayload)
	if err := json.NewDecoder(resp.Body).Decode(&getPayloadResponse); err != nil {
		log.WithError(err).Warn("getPayload request failed to decode")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	capellaExecutionPayload := getPayloadResponse.ExecutionPayloadToCapellaExecutionPayload()
	getPayloadResponseVersioned := capellaAPISpec.VersionedExecutionPayload{Version: VersionCapella, Capella: &capellaExecutionPayload, Bellatrix: nil}
	PayloadResponse := common.VersionedExecutionPayload{Bellatrix: nil, Capella: &getPayloadResponseVersioned}

	errs := api.redis.SetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered, slot)
	if errs != nil {
		log.WithError(errs).Error("Couldn't Set Payload Delivered Slot")
	}

	api.RespondOK(w, &PayloadResponse)
	log = log.WithFields(logrus.Fields{
		"blockNumber": payload.BlockNumber(),
	})
	log.Info("execution payload delivered")

}

func (api *RelayAPI) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	api.getPayloadCallsInFlight.Add(1)
	defer api.getPayloadCallsInFlight.Done()

	ua := req.UserAgent()
	log := api.log.WithFields(logrus.Fields{
		"method":        "getPayload",
		"ua":            ua,
		"mevBoostV":     common.GetMevBoostVersionFromUserAgent(ua),
		"contentLength": req.ContentLength,
	})

	payload := new(common.SignedBlindedBeaconBlock)
	capellaPayload := new(capellaAPI.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(capellaPayload); err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.WithError(err).Error("getPayload request failed to decode (i/o timeout)")
		} else {
			log.WithError(err).Warn("getPayload request failed to decode")
		}
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload.Capella = capellaPayload

	slot := payload.Slot()
	blockHash := payload.BlockHash()
	log = log.WithFields(logrus.Fields{
		"slot":      slot,
		"blockHash": payload.BlockHash(),
		"idArg":     req.URL.Query().Get("id"),
	})

	log.Debug("getPayload request received")

	proposerPubkey, found := api.datastore.GetKnownValidatorPubkeyByIndex(payload.ProposerIndex())
	if !found {
		log.Errorf("could not find proposer pubkey for index %d", payload.ProposerIndex())
		api.RespondError(w, http.StatusBadRequest, "could not match proposer index to pubkey")
		return
	}

	log = log.WithField("pubkeyFromIndex", proposerPubkey)

	// Get the proposer pubkey based on the validator index from the payload
	pk, err := types.HexToPubkey(proposerPubkey.String())
	if err != nil {
		log.WithError(err).Warn("could not convert pubkey to types.PublicKey")
		api.RespondError(w, http.StatusBadRequest, "could not convert pubkey to types.PublicKey")
		return
	}

	// Verify the signature
	ok, err := types.VerifySignature(payload.Message(), api.opts.EthNetDetails.DomainBeaconProposerCapella, pk[:], payload.Signature())
	if !ok || err != nil {
		log.WithError(err).Warn("could not verify payload signature")
		api.RespondError(w, http.StatusBadRequest, "could not verify payload signature")
		return
	}

	// Get the response - from memory, Redis or DB
	// note that mev-boost might send getPayload for bids of other relays, thus this code wouldn't find anything
	blockSubmission, err := api.datastore.GetGetPayloadHeaderResponse(slot, proposerPubkey.String(), blockHash)
	if err != nil || blockSubmission == nil {
		log.WithError(err).Warn("failed getting execution payload (1/2)")
		time.Sleep(time.Duration(timeoutGetPayloadRetryMs) * time.Millisecond)

		// Try again
		blockSubmission, err = api.datastore.GetGetPayloadHeaderResponse(slot, proposerPubkey.String(), blockHash)
		if err != nil {
			log.WithError(err).Error("failed getting execution payload (2/2) - due to error")
			api.RespondError(w, http.StatusBadRequest, err.Error())
			return
		} else if blockSubmission == nil {
			log.Warn("failed getting execution payload (2/2)")
			api.RespondError(w, http.StatusBadRequest, "no execution payload for this request")
			return
		}
	}

	postBody, _ := json.Marshal(payload.Capella)
	resp, err := http.Post(blockSubmission.API, "application/json", bytes.NewReader(postBody))
	if err != nil {
		log.Fatalf("An Error Occured %v", err)
		api.RespondError(w, http.StatusInternalServerError, "Couldn't Send Request To Builder")
		return
	}

	defer resp.Body.Close()
	// Check is the response is 200
	if resp.StatusCode != http.StatusOK {
		log.WithError(err).Error("getPayload request failed")
		response, _ := io.ReadAll(resp.Body)
		api.RespondError(w, http.StatusBadRequest, string(response))
		return
	}

	getPayloadResponse := new(common.CapellaExecutionPayload)
	if err := json.NewDecoder(resp.Body).Decode(&getPayloadResponse); err != nil {
		log.WithError(err).Warn("getPayload request failed to decode")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	capellaExecutionPayload := getPayloadResponse.ExecutionPayloadToCapellaExecutionPayload()
	getPayloadResponseVersioned := capellaAPISpec.VersionedExecutionPayload{Version: VersionCapella, Capella: &capellaExecutionPayload, Bellatrix: nil}
	PayloadResponse := common.VersionedExecutionPayload{Bellatrix: nil, Capella: &getPayloadResponseVersioned}

	errs := api.redis.SetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered, slot)
	if errs != nil {
		log.WithError(errs).Error("Couldn't Set Payload Delivered Slot")
	}

	api.RespondOK(w, &PayloadResponse)
	log = log.WithFields(logrus.Fields{
		"Slot":        payload.Slot(),
		"blockNumber": payload.BlockNumber(),
	})
	log.Info("execution payload delivered")

}

// --------------------
//  BLOCK BUILDER APIS
// --------------------

// updatedExpectedRandao updates the prev_randao field we expect from builder block submissions
func (api *RelayAPI) updatedExpectedRandao(slot uint64) {
	api.log.Infof("updating randao for %d ...", slot)
	api.expectedPrevRandaoLock.Lock()
	latestKnownSlot := api.expectedPrevRandao.slot
	if slot < latestKnownSlot || slot <= api.expectedPrevRandaoUpdating { // do nothing slot is already known or currently being updated
		api.log.Debugf("- abort updating randao - slot %d, latest: %d, updating: %d", slot, latestKnownSlot, api.expectedPrevRandaoUpdating)
		api.expectedPrevRandaoLock.Unlock()
		return
	}
	api.expectedPrevRandaoUpdating = slot
	api.expectedPrevRandaoLock.Unlock()

	// get randao from BN
	api.log.Debugf("- querying BN for randao for slot %d", slot)
	randao, err := api.beaconClient.GetRandao(slot)
	if err != nil {
		api.log.WithField("slot", slot).WithError(err).Warn("failed to get randao from beacon node")
		api.expectedPrevRandaoLock.Lock()
		api.expectedPrevRandaoUpdating = 0
		api.expectedPrevRandaoLock.Unlock()
		return
	}

	// after request, check if still the latest, then update
	api.expectedPrevRandaoLock.Lock()
	defer api.expectedPrevRandaoLock.Unlock()
	targetSlot := slot + 1
	api.log.Debugf("- after BN randao: slot %d, targetSlot: %d latest: %d", slot, targetSlot, api.expectedPrevRandao.slot)

	// update if still the latest
	if targetSlot >= api.expectedPrevRandao.slot {
		api.expectedPrevRandao = randaoHelper{
			slot:       targetSlot, // the retrieved prev_randao is for the next slot
			prevRandao: randao.Data.Randao,
		}
		api.log.WithField("slot", slot).Infof("updated expected prev_randao to %s for slot %d", randao.Data.Randao, targetSlot)
	}
}

func (api *RelayAPI) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (api *RelayAPI) handleSubmitNewBlock(w http.ResponseWriter, req *http.Request) {
	receivedAt := time.Now().UTC()
	log := api.log.WithFields(logrus.Fields{
		"method":        "submitNewBlock",
		"contentLength": req.ContentLength,
	})

	payload := new(common.BuilderSubmitBlockRequest)

	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		log.WithError(err).Warn("could not decode payload")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if payload.Message == nil || payload.ExecutionPayloadHeader == nil || payload.Endpoint == "" {
		api.RespondError(w, http.StatusBadRequest, "missing parts of the payload")
		return
	}

	log = log.WithFields(logrus.Fields{
		"slot":          payload.Message.Slot,
		"builderPubkey": payload.Message.BuilderPubkey.String(),
		"blockHash":     payload.Message.BlockHash.String(),
	})

	// Timestamp check
	expectedTimestamp := api.genesisInfo.Data.GenesisTime + (payload.Message.Slot * 12)
	if payload.ExecutionPayloadHeader.Timestamp != expectedTimestamp {
		log.Warnf("incorrect timestamp. got %d, expected %d", payload.ExecutionPayloadHeader.Timestamp, expectedTimestamp)
		api.RespondError(w, http.StatusBadRequest, fmt.Sprintf("incorrect timestamp. got %d, expected %d", payload.ExecutionPayloadHeader.Timestamp, expectedTimestamp))
		return
	}

	// randao check 1:
	// - querying the randao from the BN if payload has a newer slot (might be faster than headSlot event)
	// - check for validity happens later, again after validation (to use some time for BN request to finish...)
	api.expectedPrevRandaoLock.RLock()
	if payload.Message.Slot > api.expectedPrevRandao.slot {
		go api.updatedExpectedRandao(payload.Message.Slot - 1)
	}
	api.expectedPrevRandaoLock.RUnlock()

	log = log.WithFields(logrus.Fields{
		"proposerPubkey": payload.Message.ProposerPubkey.String(),
		"parentHash":     payload.Message.ParentHash.String(),
		"value":          payload.Message.Value.String(),
	})

	slotStr, err := api.redis.GetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered)
	if err != nil && !errors.Is(err, redis.Nil) {
		log.WithError(err).Error("failed to get delivered payload slot from redis")
		api.RespondError(w, http.StatusBadRequest, "failed to get delivered payload slot from redis")
		return
	} else if err != nil && errors.Is(err, redis.Nil) {
		log.Info("No Slot Payload Not Sent To Relayer, Bid Submitted")
	} else {
		slotLastPayloadDelivered, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			log.WithError(err).Errorf("failed to parse delivered payload slot from redis: %s", slotStr)
			api.RespondError(w, http.StatusBadRequest, "failed to parse delivered payload slot")
			return
		} else if payload.Message.Slot <= slotLastPayloadDelivered {
			fmt.Println("rejecting submission because payload for this slot was already delivered")
			api.RespondError(w, http.StatusBadRequest, "payload for this slot was already delivered")
			return
		}
	}

	if payload.Message.Slot <= api.headSlot.Load() {
		api.log.Info("submitNewBlock failed: submission for past slot")
		api.RespondError(w, http.StatusBadRequest, "submission for past slot")
		return
	}

	// Don't accept blocks with 0 value
	if payload.Message.Value.String() == ZeroU256.String() {
		api.log.Info("submitNewBlock failed: block with 0 value or no txs")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Sanity check the submission
	err = SanityCheckBuilderBlockSubmission(payload)
	if err != nil {
		log.WithError(err).Info("block submission sanity checks failed")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// get the latest randao and check again, it might have updated in the meantime)
	api.expectedPrevRandaoLock.RLock()
	expectedRandao := api.expectedPrevRandao
	api.expectedPrevRandaoLock.RUnlock()
	if expectedRandao.slot != payload.Message.Slot { // we still don't have the prevrandao yet
		log.Warn("prev_randao is not known yet")
		api.RespondError(w, http.StatusInternalServerError, "prev_randao is not known yet")
		return
	} else if expectedRandao.prevRandao != fmt.Sprintf("0x%x", payload.ExecutionPayloadHeader.PrevRandao[:]) {
		msg := fmt.Sprintf("incorrect prev_randao - got: %s, expected: %s", fmt.Sprintf("0x%x", payload.ExecutionPayloadHeader.PrevRandao[:]), expectedRandao.prevRandao)
		log.Info(msg)
		api.RespondError(w, http.StatusBadRequest, msg)
		return
	}

	pubkey, err := crypto.Ecrecover(crypto.Keccak256Hash(payload.Signature[:]).Bytes(), payload.EcdsaSignature[:])
	if err != nil {
		log.Error("Could not recover ECDSA pubkey", "err", err)
		api.RespondError(w, http.StatusServiceUnavailable, "Could not recover ECDSA pubkey")
		return
	}
	ecdsaPubkey, err := crypto.UnmarshalPubkey(pubkey)
	if err != nil {
		log.Error("Could not recover ECDSA pubkey", "err", err)
		api.RespondError(w, http.StatusServiceUnavailable, "Could not recover ECDSA pubkey")
		return
	}
	pubkeyAddress := crypto.PubkeyToAddress(*ecdsaPubkey)

	if strings.ToLower(pubkeyAddress.String()) != strings.ToLower(payload.BuilderWalletAddress.String()) {
		log.Error("ECDSA pubkey does not match wallet address", "err", err, "pubkeyAddress", pubkeyAddress.String(), "walletAddress", payload.BuilderWalletAddress.String())
		api.RespondError(w, http.StatusServiceUnavailable, "ECDSA pubkey does not match wallet address")
		return
	}

	builderTransaction, _ := json.Marshal(payload.PayoutPoolTransaction)
	RPBSMessage := common.RpbsCommitMessage{BuilderWalletAddress: &payload.BuilderWalletAddress, Slot: payload.Message.Slot, Amount: payload.Message.Value.BigInt().Uint64(), TxBytes: string(builderTransaction)}

	RPBSCommitResponse, err := api.RPBS.RPBSCommits(&RPBSMessage)
	if err != nil {
		log.Error("Could Not Calculate RPBS", "err", err)
		api.RespondError(w, http.StatusServiceUnavailable, "Could Not Calculate RPBS")
		return
	}

	defer func() {
		err := api.db.SaveBuilderBlockSubmission(payload, RPBSCommitResponse, string(builderTransaction))
		if err != nil {
			log.WithError(err).WithField("payload", payload).Error("saving builder block submission to database failed")
			return
		}
	}()

	// Ensure this request is still the latest one
	latestPayloadReceivedAt, err := api.redis.GetBuilderLatestPayloadReceivedAt(payload.Message.Slot, payload.Message.BuilderPubkey.String(), payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String())
	if err != nil {
		log.WithError(err).Error("failed getting latest payload receivedAt from redis")
	} else if receivedAt.UnixMilli() < latestPayloadReceivedAt {
		log.Infof("already have a newer payload: now=%d / prev=%d", receivedAt.UnixMilli(), latestPayloadReceivedAt)
		api.RespondError(w, http.StatusBadRequest, "already using a newer payload")
		return
	}

	// Prepare the response data
	signedBuilderBid, err := BuilderSubmitBlockRequestToSignedBuilderBid(payload, api.blsSk, api.publicKey, api.opts.EthNetDetails.DomainBuilder)
	if err != nil {
		log.WithError(err).Error("could not sign builder bid")
		api.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	getHeaderResponse := common.GetHeaderResponse{
		Version: VersionCapella,
		Data:    signedBuilderBid,
	}

	getPayloadHeaderResponse := common.GetPayloadHeaderResponse{
		Version: VersionCapella,
		Data:    payload.ExecutionPayloadHeader,
		API:     payload.Endpoint,
	}

	bidTrace := common.BidTraceV2{
		BidTrace:    *payload.Message,
		BlockNumber: payload.ExecutionPayloadHeader.BlockNumber,
		NumTx:       0,
	}

	//
	// Save to Redis
	//
	// first the trace
	err = api.redis.SaveBidTrace(&bidTrace)
	if err != nil {
		log.WithError(err).Error("failed saving bidTrace in redis")
		fmt.Println(err.Error())
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// save execution payload (getPayload response)
	err = api.redis.SaveExecutionPayloadHeader(payload.Message.Slot, payload.Message.ProposerPubkey.String(), payload.Message.BlockHash.String(), &getPayloadHeaderResponse)
	if err != nil {
		log.WithError(err).Error("failed saving execution payload in redis")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// save this builder's latest bid
	err = api.redis.SaveLatestBuilderBid(payload.Message.Slot, payload.Message.BuilderPubkey.String(), payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String(), receivedAt, &getHeaderResponse)
	if err != nil {
		log.WithError(err).Error("could not save latest builder bid")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// recalculate top bid
	err = api.redis.UpdateTopBid(payload.Message.Slot, payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String())
	if err != nil {
		log.WithError(err).Error("could not compute top bid")
		api.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	fmt.Println(fmt.Sprintf("https://relayer.0xblockswap.com/eth/v1/builder/header/%d/%s/%s", payload.Message.Slot, payload.Message.ParentHash.String(), payload.Message.ProposerPubkey.String()))
	//
	// all done
	//
	log.WithFields(logrus.Fields{
		"proposerPubkey": payload.Message.ProposerPubkey.String(),
		"value":          payload.Message.Value.String(),
	}).Info("received block from builder")

	api.RespondOK(w, &RPBSCommitResponse)

}

func (api *RelayAPI) handlePublicKey(w http.ResponseWriter, req *http.Request) {
	publicKey, err := api.RPBS.PublicKey()
	if err != nil {
		api.RespondError(w, http.StatusInternalServerError, err.Error())
	}
	api.RespondOK(w, &publicKey)
}
