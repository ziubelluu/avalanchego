// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chameleonhash

import (
	"fmt"

	"github.com/ava-labs/libevm/common"

	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/contract"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/modules"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/precompile/precompileconfig"
)

var _ contract.Configurator = (*configurator)(nil)

// ConfigKey is the json config key for this precompile.
const ConfigKey = "chameleonHashConfig"

// ContractAddress sits in the 0x03.. range reserved for precompiles added by
// forks of subnet-evm. Ordinary contracts call it for chameleon hashing.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000000")

// Module registers the ChameleonHash precompile.
var Module = modules.Module{
	ConfigKey:    ConfigKey,
	Address:      ContractAddress,
	Contract:     ChameleonHashPrecompile,
	Configurator: &configurator{},
}

type configurator struct{}

func init() {
	if err := modules.RegisterModule(Module); err != nil {
		panic(err)
	}
}

// MakeConfig returns a zero-valued config for JSON unmarshaling.
func (*configurator) MakeConfig() precompileconfig.Config {
	return new(Config)
}

// Configure has nothing to seed: the precompile is stateless.
func (*configurator) Configure(_ precompileconfig.ChainConfig, cfg precompileconfig.Config, _ contract.StateDB, _ contract.ConfigurationBlockContext) error {
	if _, ok := cfg.(*Config); !ok {
		return fmt.Errorf("expected config type %T, got %T: %v", &Config{}, cfg, cfg)
	}
	return nil
}
