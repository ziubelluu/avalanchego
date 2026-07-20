// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package evm

import (
	"fmt"
	"net/http"

	"github.com/ava-labs/libevm/log"

	"github.com/ava-labs/avalanchego/api"
	"github.com/ava-labs/avalanchego/graft/subnet-evm/plugin/evm/client"
	"github.com/ava-labs/avalanchego/utils/profiler"
)

// Admin is the API service for admin API calls
type Admin struct {
	vm       *VM
	profiler profiler.Profiler
}

func NewAdminService(vm *VM, performanceDir string) *Admin {
	return &Admin{
		vm:       vm,
		profiler: profiler.New(performanceDir),
	}
}

// StartCPUProfiler starts a cpu profile writing to the specified file
func (p *Admin) StartCPUProfiler(*http.Request, *struct{}, *api.EmptyReply) error {
	log.Info("Admin: StartCPUProfiler called")

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	return p.profiler.StartCPUProfiler()
}

// StopCPUProfiler stops the cpu profile
func (p *Admin) StopCPUProfiler(*http.Request, *struct{}, *api.EmptyReply) error {
	log.Info("Admin: StopCPUProfiler called")

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	return p.profiler.StopCPUProfiler()
}

// MemoryProfile runs a memory profile writing to the specified file
func (p *Admin) MemoryProfile(*http.Request, *struct{}, *api.EmptyReply) error {
	log.Info("Admin: MemoryProfile called")

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	return p.profiler.MemoryProfile()
}

// LockProfile runs a mutex profile writing to the specified file
func (p *Admin) LockProfile(*http.Request, *struct{}, *api.EmptyReply) error {
	log.Info("Admin: LockProfile called")

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	return p.profiler.LockProfile()
}

func (p *Admin) SetLogLevel(_ *http.Request, args *client.SetLogLevelArgs, _ *api.EmptyReply) error {
	log.Info("EVM: SetLogLevel called", "logLevel", args.Level)

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	if err := p.vm.logger.SetLogLevel(args.Level); err != nil {
		return fmt.Errorf("failed to parse log level: %w ", err)
	}
	return nil
}

func (p *Admin) GetVMConfig(_ *http.Request, _ *struct{}, reply *client.ConfigReply) error {
	reply.Config = &p.vm.config
	return nil
}

// RedactStateDeposit runs a chameleon redaction of a deposit. Needs the trapdoor
// in the env and an approved committee proof, else it fails and changes nothing.
func (p *Admin) RedactStateDeposit(r *http.Request, args *client.RedactStateDepositArgs, reply *client.RedactStateDepositReply) error {
	log.Info("Admin: RedactStateDeposit called", "block", args.OriginalBlockHash, "id", args.DepositID)

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	hash, rPrime, err := p.vm.RedactStateDeposit(
		r.Context(),
		args.OriginalBlockHash,
		args.DepositContract,
		args.DepositID,
		args.Blob,
		args.Randomness,
		args.NewBlob,
		args.Proof,
		args.PChainHeight,
	)
	if err != nil {
		return err
	}
	reply.RedactedBlockHash = hash
	reply.NewRandomness = rPrime
	return nil
}

// RedactTransactions runs a tx-channel (old/new-link) redaction of a block.
// Needs an approved committee proof, else it fails and changes nothing.
func (p *Admin) RedactTransactions(r *http.Request, args *client.RedactTransactionsArgs, reply *client.RedactTransactionsReply) error {
	log.Info("Admin: RedactTransactions called", "block", args.OriginalBlockHash)

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	hash, err := p.vm.RedactTransactions(r.Context(), args.OriginalBlockHash, args.Proof)
	if err != nil {
		return err
	}
	reply.RedactedBlockHash = hash
	return nil
}

// ApproveRedaction records this validator's manual approval of a redaction
// proposal, so the node signs it when the committee aggregator asks.
func (p *Admin) ApproveRedaction(_ *http.Request, args *client.ApproveRedactionArgs, reply *client.ApproveRedactionReply) error {
	log.Info("Admin: ApproveRedaction called", "kind", args.Kind)

	p.vm.vmLock.Lock()
	defer p.vm.vmLock.Unlock()

	id, err := p.vm.ApproveRedaction(args.Kind, args.Proposal)
	if err != nil {
		return err
	}
	reply.MessageID = id
	return nil
}

// CollectRedactionProof gathers the committee signatures into a proof. It talks
// to the network, so it doesn't take the VM lock.
func (p *Admin) CollectRedactionProof(r *http.Request, args *client.CollectRedactionProofArgs, reply *client.CollectRedactionProofReply) error {
	log.Info("Admin: CollectRedactionProof called", "kind", args.Kind)

	proofBytes, err := p.vm.CollectRedactionProof(r.Context(), args.Kind, args.Proposal)
	if err != nil {
		return err
	}
	reply.Proof = proofBytes
	return nil
}
