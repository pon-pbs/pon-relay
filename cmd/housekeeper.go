package cmd

import (
	"net/url"
	"strings"

	"github.com/spf13/cobra"
	"pon-relay.com/beaconclient"
	"pon-relay.com/common"
	"pon-relay.com/database"
	"pon-relay.com/datastore"
	"pon-relay.com/ponPool"
	"pon-relay.com/services/housekeeper"
)

func init() {
	rootCmd.AddCommand(housekeeperCmd)
	housekeeperCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	housekeeperCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	housekeeperCmd.Flags().StringSliceVar(&beaconNodeURIs, "beacon-uris", defaultBeaconURIs, "beacon endpoints")
	housekeeperCmd.Flags().StringVar(&redisURI, "redis-uri", defaultRedisURI, "redis uri")
	housekeeperCmd.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	housekeeperCmd.Flags().StringVar(&ponSubgraph, "pon-pool", defaultPostgresDSN, "PON Registry Subgraph URL")

	housekeeperCmd.Flags().StringVar(&network, "network", defaultNetwork, "Which network to use")
}

var housekeeperCmd = &cobra.Command{
	Use:   "housekeeper",
	Short: "Service that runs in the background and does various housekeeping (removing old bids, updating proposer duties, saving metrics, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		log := common.LogSetup(logJSON, logLevel).WithField("service", "relay/housekeeper")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon clients and ensure it's synced
		if len(beaconNodeURIs) == 0 {
			log.Fatalf("no beacon endpoints specified")
		}
		log.Infof("Using beacon endpoints: %s", strings.Join(beaconNodeURIs, ", "))
		var beaconInstances []beaconclient.IBeaconInstance
		for _, uri := range beaconNodeURIs {
			beaconInstances = append(beaconInstances, beaconclient.NewProdBeaconInstance(log, uri))
		}
		beaconClient := beaconclient.NewMultiBeaconClient(log, beaconInstances)

		// Connect to Redis and setup the datastore
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		// Connect to Postgres
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}
		ponPool := ponPool.NewPonPool(ponSubgraph, " ")

		opts := &housekeeper.HousekeeperOpts{
			Log:          log,
			Redis:        redis,
			DB:           db,
			BeaconClient: beaconClient,
			PonPool:      ponPool,
		}
		service := housekeeper.NewHousekeeper(opts)
		log.Info("Starting housekeeper service...")
		err = service.Start()
		log.WithError(err).Fatalf("Failed to start housekeeper")
	},
}
