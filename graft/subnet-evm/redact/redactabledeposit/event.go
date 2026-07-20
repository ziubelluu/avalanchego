// Copyright (C) 2019, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package redactabledeposit

// DepositedEventData is the data of a Deposited log: just the digest. The
// opening (blob, r) is never logged, so it doesn't end up in the receipts.
type DepositedEventData struct {
	Digest []byte
}

// UnpackDepositedEventData decodes a Deposited log's data.
func UnpackDepositedEventData(dataBytes []byte) (DepositedEventData, error) {
	var data DepositedEventData
	err := ABI.UnpackIntoInterface(&data, "Deposited", dataBytes)
	return data, err
}
