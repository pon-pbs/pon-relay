package cmd

import (
	"os"

	"pon-relay.com/common"
)

var (
	defaultNetwork     = common.GetEnv("NETWORK", "")
	defaultBeaconURIs  = common.GetSliceEnv("BEACON_URIS", []string{"http://localhost:3500"})
	defaultRedisURI    = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultPostgresDSN = common.GetEnv("POSTGRES_DSN", "")
	defaultLogJSON     = os.Getenv("LOG_JSON") != ""
	defaultLogLevel    = common.GetEnv("LOG_LEVEL", "info")

	beaconNodeURIs []string
	redisURI       string
	postgresDSN    string

	logJSON  bool
	logLevel string

	network string
)
