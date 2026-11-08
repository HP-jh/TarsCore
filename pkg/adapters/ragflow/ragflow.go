package ragflow

type Adapter struct {
	BaseURL string
	APIKey  string
}

func New(baseURL, apiKey string) *Adapter {
	return &Adapter{BaseURL: baseURL, APIKey: apiKey}
}

func (a *Adapter) Name() string { return "RAGFlow" }
