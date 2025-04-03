package models

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

type (
	// DAG represents a Directed Acyclic Graph storing transactions.
	DAG struct {
		Nodes map[string]*Transaction
		Lock  sync.RWMutex
	}

	// Transaction represents a single transaction in the DAG.
	Transaction struct {
		Id        string   `json:"index"`
		TimeStamp string   `json:"timestamp"`
		Parents   []string `json:"parents"`
		Data      any      `json:"Data"`
		Hash      string   `json:"hash"`
		PrevHash  string   `json:"prevhash"`
		Signature string   `json:"signature"`
	}

	// DID represents a decentralized identifier with its data.
	DID struct {
		DID               string `json:"DID"`
		Owner             string `json:"owner"`
		OwnerSignature    string `json:"owner_signature"`
		VerifiedBy        string `json:"verifiedBy"`
		VerifierSignature string `json:"verifierSignature"`
	}
)

func (t *Transaction) UnmarshalJSON(data []byte) error {
	type Alias Transaction
	aux := &struct {
		Data *DID `json:"Data"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	t.Data = aux.Data
	return nil
}

// NewDAG initializes a new DAG structure with a signed genesis transaction.
func NewDAG() *DAG {
	dag := &DAG{Nodes: make(map[string]*Transaction)}

	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Create genesis DID data
	genesisDID := DID{
		DID:        "genesis-did",
		Owner:      "system",
		VerifiedBy: "system-verifier",
	}

	// Sign the DID data to create OwnerSignature
	didData := fmt.Sprintf("%s:%s:%s", genesisDID.DID, genesisDID.Owner, genesisDID.VerifiedBy)
	didHash := sha256.Sum256([]byte(didData))
	signature, err := crypto.Sign(didHash[:], privateKey)
	if err != nil {
		log.Fatalf("Failed to sign genesis DID: %v", err)
	}
	genesisDID.OwnerSignature = hex.EncodeToString(signature)

	// Create the genesis transaction
	genesisTx := &Transaction{
		Id:        uuid.New().String(),
		TimeStamp: time.Now().UTC().Format(time.RFC3339),
		Parents:   []string{},
		Data:      genesisDID,
		PrevHash:  "",
	}

	// Compute the transaction's hash
	jsonData, err := json.Marshal(genesisTx.Data)
	if err != nil {
		log.Fatalf("Error marshaling genesis data: %v", err)
	}
	dataToHash := string(jsonData) + genesisTx.PrevHash + genesisTx.TimeStamp
	hash := sha256.Sum256([]byte(dataToHash))
	hashStr := hex.EncodeToString(hash[:])

	// Sign the transaction hash with the private key
	txSignature, err := crypto.Sign(hash[:], privateKey)
	if err != nil {
		log.Fatalf("Failed to sign genesis transaction: %v", err)
	}
	txSignatureHex := hex.EncodeToString(txSignature)
	genesisTx.Signature = txSignatureHex

	// Verify the transaction signature
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Error casting public key to ECDSA")
	}

	recoveredPub, err := crypto.Ecrecover(hash[:], txSignature)
	if err != nil {
		log.Fatalf("Failed to recover public key: %v", err)
	}
	originalPubBytes := crypto.FromECDSAPub(publicKeyECDSA)
	if !bytes.Equal(recoveredPub, originalPubBytes) {
		log.Fatal("Recovered public key does not match original")
	}

	sigNoV := txSignature[:64]
	verified := crypto.VerifySignature(originalPubBytes, hash[:], sigNoV)
	if !verified {
		log.Fatal("Transaction signature verification failed")
	}

	// Set the transaction's hash and add to DAG
	genesisTx.Hash = hashStr
	dag.Nodes[hashStr] = genesisTx

	return dag
}

// AddDID adds a new DID transaction to the DAG and links it to parent transactions.
func (dag *DAG) AddDID(tx *Transaction) (string, error) {
	dag.Lock.Lock()
	defer dag.Lock.Unlock()
	if tx.Data == nil {
		return " ", errors.New("transaction data cannot be nil")
	}

	if _, ok := tx.Data.(*DID); !ok {
		return " ", fmt.Errorf("invalid data type %T, expected *DID", tx.Data)
	}

	layout := time.RFC3339

	currentTxTime, err := time.Parse(layout, tx.TimeStamp)
	if err != nil {
		return " ", fmt.Errorf("error parsing new transaction's timestamp: %v", err)
	}

	var parents []string

	for hash, transaction := range dag.Nodes {
		timeOfPrevTx, err := time.Parse(layout, transaction.TimeStamp)
		if err != nil {
			log.Printf("Error parsing existing transaction's timestamp: %v", err)
			continue
		}
		if timeOfPrevTx.Before(currentTxTime) {
			parents = append(parents, hash)
		}
		if len(parents) >= 3 {
			break
		}
	}

	tx.Parents = parents

	jsonData, err := json.Marshal(tx.Data)
	if err != nil {
		return " ", fmt.Errorf("error marshaling transaction data: %v", err)
	}

	parentsHashCombined := ""
	for _, parentHash := range parents {
		parentsHashCombined += parentHash
	}

	hash := sha256.Sum256([]byte(string(jsonData) + parentsHashCombined + tx.PrevHash + tx.TimeStamp))
	hashStr := hex.EncodeToString(hash[:])
	tx.Id = uuid.New().String()
	tx.Hash = hashStr

	dag.Nodes[hashStr] = tx
	return tx.Id, nil
}

// GetLatestTxHash returns the hash of the most recent transaction by timestamp.
func (dag *DAG) GetLatestTxHash() (string, error) {
	dag.Lock.RLock()
	defer dag.Lock.RUnlock()

	if len(dag.Nodes) == 0 {
		return "", fmt.Errorf("no transactions in DAG")
	}

	var latestTx *Transaction
	var latestTxHash string

	for hash, tx := range dag.Nodes {
		txTime, err := time.Parse(time.RFC3339, tx.TimeStamp)
		if err != nil {
			return "", fmt.Errorf("error parsing transaction's timestamp: %v", err)
		}

		if latestTx == nil {
			latestTx = tx
			latestTxHash = hash
			continue
		}

		currentLatestTime, _ := time.Parse(time.RFC3339, latestTx.TimeStamp)
		if txTime.After(currentLatestTime) {
			latestTx = tx
			latestTxHash = hash
		}
	}

	return latestTxHash, nil
}
