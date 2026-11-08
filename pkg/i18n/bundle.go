package i18n

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadBundle(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle %s: %w", path, err)
	}
	
	var bundle map[string]string
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse bundle %s: %w", path, err)
	}
	
	return bundle, nil
}
