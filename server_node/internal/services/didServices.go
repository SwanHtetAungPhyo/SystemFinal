package services

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SwanHtetAungPhyo/server_node/internal/model"
	"github.com/SwanHtetAungPhyo/server_node/pkg/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-resty/resty/v2"
	"github.com/mr-tron/base58"
	"log"
	"time"

	"github.com/sirupsen/logrus"
)

type DidMethods interface {
	AuthAndGenerateDID(req model.FinalRegistration) string
}
type DidService struct {
	logger *logrus.Logger
	key    *ecdsa.PrivateKey
}

func NewDidService(logger *logrus.Logger, key *ecdsa.PrivateKey) *DidService {
	return &DidService{logger: logger,
		key: key}

}

func (d *DidService) AuthAndGenerateDID(req model.ReqToServer) (string, string, bool) {
	// ✅ Decode Public Key from Hex
	log.Printf("Received DIDHASH (server): %s", req.Registration.DIDHASH)

	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil {
		fmt.Println("Failed to decode public key:", err)
		return "", " ", false
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		fmt.Println("Failed to parse public key:", err)
		return "", " ", false
	}
	_ = pubKey

	hashBytes, err := base58.Decode(req.Registration.DIDHASH)
	if err != nil {
		fmt.Println("Failed to decode hash:", err)
		return "", " ", false
	}

	log.Printf("Decoded hashBytes (server): %x", hashBytes)
	signatureBytes, err := base58.Decode(req.Signature)
	if err != nil {
		fmt.Println("Failed to decode signature:", err)
		return "1", " ", false
	}

	// ✅ Prepare Signature for Verification (remove V byte)
	if len(signatureBytes) != 65 {
		fmt.Println("Invalid signature length")
		return "1", " ", false
	}
	signatureWithoutV := signatureBytes[:64]

	// ✅ Verify Signature
	isValid := crypto.VerifySignature(pubKeyBytes, hashBytes, signatureWithoutV)
	if !isValid {
		fmt.Println("Signature verification failed")
		return "1", " ", false
	}

	log.Println("✅ Signature verified successfully")
	did := "did:kyc:" + base58.Encode(hashBytes)
	log.Println(did)
	didTx, err := sendToRemoteChain(did, req.Registration.PublicKey, d.key)
	if err != nil {
		fmt.Println("Failed to send to remote chain:", err)
		return "1", " ", false
	}
	return did, didTx, true
}

func sendToRemoteChain(did, publicKeyByOwner string, serverPrivateKey *ecdsa.PrivateKey) (string, error) {
	// Call to the chain for the latest Tx
	latestHash, err := callToServerToGetLatestBlockHash()
	if err != nil {
		fmt.Println("Failed to get latest block hash:", err.Error())
		return " ", err
	}
	sendToServerWithNodeSignature := &model.Transaction{
		TimeStamp: time.Now().Format(time.RFC3339),
		Data: &model.DID{ // <-- Use pointer here
			DID:   did,
			Owner: publicKeyByOwner,
		},
		PrevHash: latestHash,
	}

	// Safe type assertion with error checking
	didData, ok := sendToServerWithNodeSignature.Data.(*model.DID)
	if !ok || didData == nil {
		return "", fmt.Errorf("invalid DID data in transaction")
	}

	// Use didData directly
	didInTxForHash := fmt.Sprintf("%s%s%s%s",
		didData.DID,
		didData.Owner,
		sendToServerWithNodeSignature.TimeStamp,
		sendToServerWithNodeSignature.PrevHash,
	)
	didHashAfterVerification := sha256.Sum256([]byte(didInTxForHash))

	signatureForDid, err := crypto.Sign(didHashAfterVerification[:], serverPrivateKey)
	if err != nil {
		fmt.Println("Failed to sign transaction:", err)
		return "", errors.New("failed to sign transaction")
	}
	sendToServerWithNodeSignature.Signature = hex.EncodeToString(signatureForDid)
	log.Printf("Data type: %T", sendToServerWithNodeSignature.Data)
	txId, err := submitToSever(sendToServerWithNodeSignature)
	if err != nil {
		fmt.Println("Failed to submit transaction:", err)
		return " ", errors.New("failed to submit transaction")
	}
	return txId, nil
}

func callToServerToGetLatestBlockHash() (string, error) {
	client := resty.New()
	resp, err := client.R().
		Get(utils.LatestBlock)
	if err != nil {
		return "", err
	}
	log.Println(resp.String(), " Latest Block Hash")
	return resp.String(), nil
}

func submitToSever(tx *model.Transaction) (string, error) {
	client := resty.New()
	resp, err := client.R().
		SetBody(tx).
		Post(utils.Submit)
	if err != nil {
		log.Println("Failed to submit transaction:", err.Error())
		return " ", err
	}
	return resp.String(), nil
}
