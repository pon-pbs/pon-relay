package common

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/ethereum/go-ethereum/log"
)

type RPBSService struct {
	endpoint string
	apiKey   string
}

func NewRPBSService(endpoint string, apiKey string) *RPBSService {
	return &RPBSService{
		endpoint: endpoint,
		apiKey:   apiKey,
	}
}

func (r *RPBSService) RPBSCommits(commitMsg *RpbsCommitMessage) (*RpbsCommitResponse, error) {

	url := r.endpoint + "/commit"

	data := fmt.Sprintf("BuilderWalletAddress: %s, Slot: %d, Amount: %d, Transaction: %s", commitMsg.BuilderWalletAddress, commitMsg.Slot, commitMsg.Amount, commitMsg.TxBytes)

	body := map[string]string{
		"commonInfo":     data,
		"blindedMessage": fmt.Sprintf("%x", sha256.Sum256([]byte(data))),
	}

	log.Info("RPBS Commit", "url", url, "body", body)

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		log.Error("could not marshal body", "url", url, "err", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error("invalid request", "url", url, "err", err)
		return nil, err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("client refused", "url", url, "err", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error("could not read response body", "url", url, "err", err)
			return nil, err
		}
		log.Error("invalid response", "url", url, "status", resp.StatusCode, "body", string(bodyBytes))
		return nil, errors.New("invalid response")
	}

	var response RpbsCommitResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		log.Error("could not decode response", "url", url, "err", err)
		return nil, err
	}
	return &response, nil
}

func (r *RPBSService) PublicKey() (string, error) {

	url := r.endpoint + "/publicKey"

	log.Info("RPBS Public Key", "url", url)

	req, err := http.NewRequest("GET", url, bytes.NewReader(nil))
	if err != nil {
		log.Error("invalid request", "url", url, "err", err)
		return " ", err
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("client refused", "url", url, "err", err)
		return " ", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error("could not read response body", "url", url, "err", err)
			return " ", err
		}
		log.Error("invalid response", "url", url, "status", resp.StatusCode, "body", string(bodyBytes))
		return " ", errors.New("invalid response")
	}

	var response string
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		log.Error("could not decode response", "url", url, "err", err)
		return " ", err
	}
	return response, nil
}
