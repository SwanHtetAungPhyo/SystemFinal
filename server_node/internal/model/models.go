package model

import "github.com/goccy/go-json"

type (
	DIDRegistryByUser struct {
		NationalIDHash string `json:"national_id_hash"`
		BiometricHash  string `json:"biometric_hash"`
		BiometricSalt  string `json:"biometric_salt"`
		CreatedTime    string `json:"created_time"`
		PublicKey      string `json:"public_key"`
	}
	Resp struct {
		DID      string            `json:"did"`
		Services map[string]string `json:"services"`
	}
	ReqToServer struct {
		Registration FinalRegistration `json:"registration"`
		PublicKey    string            `json:"public_key"`
		Signature    string            `json:"signature"`
	}
	FinalRegistration struct {
		DIDHASH     string `json:"did_hash"`
		CreatedTime string `json:"created"`
		PublicKey   string `json:"public_key"`
		Signature   string `json:"signature"`
	}
	Transaction struct {
		Id        int      `json:"index"`
		TimeStamp string   `json:"timestamp"`
		Parents   []string `json:"parents"`
		Data      any      `json:"Data"`
		Hash      string   `json:"hash"`
		PrevHash  string   `json:"prevhash"`
		Signature string   `json:"signature"`
	}

	// DID represents a decentralized identifier with its data.
	DID struct {
		DID   string `json:"DID"`
		Owner string `json:"owner"`
	}

	LatestHashResponse struct {
		LatestHash string `json:"latest_hash"`
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
