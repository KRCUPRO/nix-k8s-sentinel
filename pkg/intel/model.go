package intel

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity represents CVSS threat severity level.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// ThreatItem models an individual CVE or security advisory.
type ThreatItem struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Component   string    `json:"component"`
	Target      string    `json:"target"` // "nixos" or "kubernetes"
	Severity    Severity  `json:"severity"`
	CVSSScore   float64   `json:"cvss_score"`
	Description string    `json:"description"`
	Mitigation  string    `json:"mitigation"`
	PublishedAt time.Time `json:"published_at"`
}

// Feed represents a collection of threat intelligence items.
type Feed struct {
	Version   string       `json:"version"`
	UpdatedAt time.Time    `json:"updated_at"`
	Items     []ThreatItem `json:"items"`
}

// ParseFeed parses raw JSON feed bytes into a validated Feed instance.
func ParseFeed(data []byte) (*Feed, error) {
	var feed Feed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse threat feed json: %w", err)
	}
	return &feed, nil
}

// FilterByTarget returns items matching the specific target ("nixos" or "kubernetes").
func (f *Feed) FilterByTarget(target string) []ThreatItem {
	var results []ThreatItem
	for _, item := range f.Items {
		if item.Target == target {
			results = append(results, item)
		}
	}
	return results
}
