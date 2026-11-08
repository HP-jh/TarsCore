package dify

import "fmt"

type Adapter struct {
	BaseURL  string
	APIKey   string
	ClientID string
}

func New(baseURL, apiKey, clientID string) *Adapter {
	return &Adapter{BaseURL: baseURL, APIKey: apiKey, ClientID: clientID}
}

func (a *Adapter) Name() string { return "Dify" }

func (a *Adapter) DiscoverTools() ([]Tool, error) {
	return []Tool{
		{Name: "dify_chat", Description: "Send message to Dify workflow"},
	}, nil
}

type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
