package ponPool

import (
	"encoding/json"
	"net/http"
	"strings"
)

type PonRegistrySubgraph struct {
	Client  http.Client
	URL     string
	API_KEY string
}

func NewPonPool(url string, apiKey string) *PonRegistrySubgraph {
	return &PonRegistrySubgraph{
		Client:  http.Client{},
		URL:     url,
		API_KEY: apiKey,
	}
}

func (s *PonRegistrySubgraph) GetBuilders() ([]Builder, error) {
	payload := strings.NewReader("{\"query\":\"{\\n  builders(first:1000){\\n    id\\n    status\\n  }\\n}\",\"variables\":{}}")
	req, err := http.NewRequest("POST", s.URL, payload)
	if err != nil {
		return nil, err
	}
	res, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	builderResponse := new(BuilderPool)
	if err := json.NewDecoder(res.Body).Decode(&builderResponse); err != nil {
		return nil, err
	}
	return builderResponse.Data.Builders, nil
}
