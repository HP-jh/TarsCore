// Package i18n provides six-language translation engine inspired by Tencent NT architecture.
// Supports real-time translation, language detection, and resource bundle management.
package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Language string

const (
	ZH Language = "zh" // Chinese Simplified
	EN Language = "en" // English
	JA Language = "ja" // Japanese
	KO Language = "ko" // Korean
	RU Language = "ru" // Russian
	AR Language = "ar" // Arabic
	FR Language = "fr" // French
)

type Bundle struct {
	lang    Language
	data    map[string]string
	loaded  bool
	path    string
}

type Engine struct {
	mu       sync.RWMutex
	bundles  map[Language]*Bundle
	currentLang Language
	hooks    []HookFunc
}

type HookFunc func(event HookEvent)

type HookEvent struct {
	Type     string        // "bundle_loaded", "language_changed", "key_added"
	Language Language      `json:"language"`
	Key      string        `json:"key,omitempty"`
	Value    string        `json:"value,omitempty"`
}

func NewEngine() *Engine {
	return &Engine{
		bundles: make(map[Language]*Bundle),
		currentLang: ZH,
	}
}

func (e *Engine) LoadBundle(lang Language, path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	_, exists := e.bundles[lang]
	if !exists {
		e.bundles[lang] = &Bundle{lang: lang, path: path}
	}
	
	bundle := e.bundles[lang]
	if bundle.loaded {
		return nil
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read bundle %s: %w", lang, err)
	}
	
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse bundle %s: %w", lang, err)
	}
	
	bundle.data = raw
	bundle.loaded = true
	
	e.fireHook(HookEvent{
		Type: "bundle_loaded",
		Language: lang,
	})
	
	return nil
}

func (e *Engine) Translate(key string, lang Language) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	bundle, ok := e.bundles[lang]
	if !ok || bundle.data == nil {
		bundle = e.bundles[EN] // fallback to English
	}
	
	if bundle == nil {
		return key // return key itself if no bundle
	}
	
	text, exists := bundle.data[key]
	if !exists {
		// Try fallback chain: current -> en -> zh -> key
		for _, fallback := range []Language{e.currentLang, EN, ZH} {
			if fb, ok := e.bundles[fallback]; ok && fb.data != nil {
				if val, found := fb.data[key]; found {
					return val
				}
			}
		}
		return key
	}
	
	return text
}

func (e *Engine) SetCurrentLang(lang Language) {
	e.mu.Lock()
	e.currentLang = lang
	e.mu.Unlock()
	
	e.fireHook(HookEvent{
		Type: "language_changed",
		Language: lang,
	})
}

func (e *Engine) GetCurrentLang() Language {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.currentLang
}

func (e *Engine) GetLanguages() []Language {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	languages := make([]Language, 0, len(e.bundles))
	for lang := range e.bundles {
		languages = append(languages, lang)
	}
	return languages
}

func (e *Engine) AddKey(lang Language, key, value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	if _, ok := e.bundles[lang]; !ok {
		e.bundles[lang] = &Bundle{lang: lang}
	}
	
	e.bundles[lang].data[key] = value
	
	e.fireHook(HookEvent{
		Type: "key_added",
		Language: lang,
		Key: key,
		Value: value,
	})
}

func (e *Engine) GetCoverage() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	coverage := make(map[string]int)
	
	// Count keys in each bundle
	maxKeys := 0
	for _, bundle := range e.bundles {
		if len(bundle.data) > maxKeys {
			maxKeys = len(bundle.data)
		}
	}
	
	if maxKeys == 0 {
		return coverage
	}
	
	for lang, bundle := range e.bundles {
		if bundle.data != nil {
			coverage[string(lang)] = (len(bundle.data) * 100) / maxKeys
		}
	}
	
	return coverage
}

func (e *Engine) fireHook(event HookEvent) {
	for _, hook := range e.hooks {
		hook(event)
	}
}

func (e *Engine) AddHook(hook HookFunc) {
	e.mu.Lock()
	e.hooks = append(e.hooks, hook)
	e.mu.Unlock()
}

// AutoDetect detects language from content (simplified - would use NLP in production)
func (e *Engine) AutoDetect(text string) Language {
	// Check for common patterns in each language
	ranges := map[Language][]rune{
		ZH: {{0x4E00, 0x9FFF}, {0x3000, 0x30FF}},
		JA: {{0x3040, 0x309F}, {0x30A0, 0x30FF}},
		KO: {{0xAC00, 0xD7AF}},
		RU: {{0x0400, 0x04FF}},
	}
	
	runes := []rune(text)
	if len(runes) == 0 {
		return EN
	}
	
	for lang, charRanges := range ranges {
		count := 0
		for _, r := range runes {
			for _, cr := range charRanges {
				if r >= cr.Start && r <= cr.End {
					count++
					break
				}
			}
		}
		if count > len(runes)*0.5 {
			return lang
		}
	}
	
	return EN
}
