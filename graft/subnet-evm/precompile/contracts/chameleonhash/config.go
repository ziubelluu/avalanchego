// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleonhash

import (
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/precompileconfig"
)

var _ precompileconfig.Config = (*Config)(nil)

// Config is the activation config for the ChameleonHash precompile. It is a
// stateless crypto primitive, so it takes no parameters.
type Config struct {
	precompileconfig.Upgrade
}

// NewConfig enables ChameleonHash at [blockTimestamp].
func NewConfig(blockTimestamp *uint64) *Config {
	return &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp}}
}

// NewDisableConfig disables ChameleonHash at [blockTimestamp].
func NewDisableConfig(blockTimestamp *uint64) *Config {
	return &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: blockTimestamp, Disable: true}}
}

// Key must match ConfigKey used in the precompile module.
func (*Config) Key() string { return ConfigKey }

// Equal returns true if [cfg] is a *Config with the same upgrade schedule.
func (c *Config) Equal(cfg precompileconfig.Config) bool {
	if c == nil {
		return cfg == nil
	}
	other, ok := cfg.(*Config)
	if !ok || other == nil {
		return false
	}
	return c.Upgrade.Equal(&other.Upgrade)
}

// Verify has nothing to validate: the precompile takes no parameters.
func (*Config) Verify(precompileconfig.ChainConfig) error { return nil }
