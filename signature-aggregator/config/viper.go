// Copyright (C) 2024, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/ava-labs/avalanchego/staking"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func NewConfig(v *viper.Viper) (Config, error) {
	cfg, err := BuildConfig(v)
	if err != nil {
		return cfg, err
	}
	if err = cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("failed to validate configuration: %w", err)
	}
	return cfg, nil
}

// Build the viper instance. The config file must be provided via the command line flag or environment variable.
// All config keys may be provided via config file or environment variable.
func BuildViper(fs *pflag.FlagSet) (*viper.Viper, error) {
	v := viper.New()
	v.AutomaticEnv()
	// Map flag names to env var names. Flags are capitalized, and hyphens are replaced with underscores.
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	if err := v.BindPFlags(fs); err != nil {
		return nil, err
	}

	// Verify required flags are set
	if !v.IsSet(ConfigFileKey) {
		DisplayUsageText()
		return nil, fmt.Errorf("config file not set")
	}

	filename := v.GetString(ConfigFileKey)
	v.SetConfigFile(filename)
	v.SetConfigType("json")
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	return v, nil
}

func SetDefaultConfigValues(v *viper.Viper) {
	v.SetDefault(LogLevelKey, defaultLogLevel)
	v.SetDefault(APIPortKey, defaultAPIPort)
	v.SetDefault(MetricsPortKey, defaultMetricsPort)
	v.SetDefault(
		SignatureCacheSizeKey,
		DefaultSignatureCacheSize,
	)
}

// BuildConfig constructs the signature aggregator config using Viper.
// The following precedence order is used. Each item takes precedence over the item below it:
//  1. Flags
//  2. Config file
//
// Returns the Config
func BuildConfig(v *viper.Viper) (Config, error) {
	// Set default values
	SetDefaultConfigValues(v)

	// Build the config from Viper
	var cfg Config

	if err := v.Unmarshal(&cfg); err != nil {
		return cfg, fmt.Errorf("failed to unmarshal viper config: %w", err)
	}

	//
	if v.IsSet(TLSKeyPathKey) || v.IsSet(TLSCertPathKey) {
		cert, err := getTLSCertFromFile(v)
		if err != nil {
			return cfg, fmt.Errorf("failed to initialize TLS certificate: %w", err)
		}
		cfg.tlsCert = &cert
	}

	return cfg, nil
}

func getTLSCertFromFile(v *viper.Viper) (tls.Certificate, error) {
	if !v.IsSet(TLSKeyPathKey) || !v.IsSet(TLSCertPathKey) {
		return tls.Certificate{}, fmt.Errorf("TLS key or cert path not set")
	}
	// Parse the staking key/cert paths and expand environment variables
	keyPath := getExpandedPath(v, TLSKeyPathKey)
	certPath := getExpandedPath(v, TLSCertPathKey)

	var keyMissing, certMissing bool

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		keyMissing = true
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		certMissing = true
	}
	if !(keyMissing && certMissing) && (keyMissing || certMissing) {
		// If only one of the key/cert pair is missing return an error
		// otherwise, create the staking key/cert pair
		return tls.Certificate{}, fmt.Errorf("TLS key or cert file is missing from configured path.", zap.String("keyPath", keyPath), zap.String("certPath", certPath))
	} else if keyMissing && certMissing {
		// Create the key/cert pair if [TLSKeyPath] and [TLSCertPath] are set but the files are missing
		if err := staking.InitNodeStakingKeyPair(keyPath, certPath); err != nil {
			return tls.Certificate{}, fmt.Errorf("couldn't generate TLS key/cert: %w", err)
		}
	}

	// Load and parse the staking key/cert
	cert, err := staking.LoadTLSCertFromFiles(keyPath, certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("couldn't read staking certificate: %w", err)
	}
	return *cert, nil
}

// getExpandedPath gets the string in viper corresponding to [key] and expands
// any variables using the OS env.
func getExpandedPath(v *viper.Viper, key string) string {
	return os.Expand(
		v.GetString(key),
		func(strVar string) string {
			return os.Getenv(strVar)
		},
	)
}
