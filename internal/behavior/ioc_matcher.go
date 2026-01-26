package behavior

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// IOCMatcher performs OpenIOC matching against collected system data
type IOCMatcher struct {
	rules []OpenIOCIndicator
	log   *zap.Logger
}

// NewIOCMatcher creates a new IOC matcher
func NewIOCMatcher(log *zap.Logger) *IOCMatcher {
	return &IOCMatcher{
		rules: []OpenIOCIndicator{},
		log:   log,
	}
}

// OpenIOC structures based on OpenIOC 1.1 specification
// Reference: https://github.com/mandiant/OpenIOC_1.1

// OpenIOCIndicator represents an OpenIOC indicator document
type OpenIOCIndicator struct {
	XMLName     xml.Name         `xml:"ioc"`
	ID          string           `xml:"id,attr"`
	LastModified time.Time       `xml:"last-modified,attr"`
	PublishedDate time.Time      `xml:"published-date,attr,omitempty"`
	Links       []IOCLink        `xml:"links>link"`
	Definition  IOCDefinition    `xml:"definition"`
	Metadata    IOCMetadata      `xml:"metadata"`
	Parameters  []IOCParameter   `xml:"parameters>param"`
}

// IOCLink represents a reference link in the IOC
type IOCLink struct {
	Rel  string `xml:"rel,attr"`
	Href string `xml:"href,attr"`
}

// IOCDefinition contains the IOC logic
type IOCDefinition struct {
	Operator string       `xml:"operator,attr"` // AND, OR
	Items    []IOCItem    `xml:"Indicator"`
}

// IOCItem represents a single indicator item
type IOCItem struct {
	ID          string      `xml:"id,attr"`
	Operator    string      `xml:"operator,attr"` // AND, OR
	Negate      bool        `xml:"negate,attr,omitempty"`
	Items       []IOCItem   `xml:"Indicator"`
	IndicatorItems []IndicatorItem `xml:"IndicatorItem"`
}

// IndicatorItem represents a specific IOC condition
type IndicatorItem struct {
	ID         string    `xml:"id,attr"`
	Condition  string    `xml:"condition,attr"` // is, contains, matches, etc.
	Negate     bool      `xml:"negate,attr,omitempty"`
	Document   string    `xml:"Context>document,attr"`
	Search     string    `xml:"Context>search,attr"`
	Content    IOCContent `xml:"Content"`
}

// IOCContent holds the actual indicator value
type IOCContent struct {
	Type  string `xml:"type,attr"` // string, int, md5, sha256, etc.
	Value string `xml:",chardata"`
}

// IOCMetadata contains IOC metadata
type IOCMetadata struct {
	ShortDescription string `xml:"short_description"`
	Description      string `xml:"description,omitempty"`
	Author           string `xml:"authored_by,omitempty"`
	AuthoredDate     string `xml:"authored_date,omitempty"`
}

// IOCParameter represents a configurable parameter
type IOCParameter struct {
	ID    string `xml:"id,attr"`
	Ref   string `xml:"ref-id,attr"`
	Name  string `xml:"name,attr"`
	Value string `xml:"content"`
}

// IOCMatch represents a matched IOC
type IOCMatch struct {
	IOCID       string    `json:"ioc_id"`
	IOCName     string    `json:"ioc_name"`
	Description string    `json:"description"`
	MatchedItem string    `json:"matched_item"`
	MatchType   string    `json:"match_type"` // file, process, network, registry
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// LoadRules loads OpenIOC rules from XML data
func (m *IOCMatcher) LoadRules(xmlData []byte) error {
	var ioc OpenIOCIndicator
	if err := xml.Unmarshal(xmlData, &ioc); err != nil {
		return fmt.Errorf("failed to parse OpenIOC XML: %w", err)
	}

	m.rules = append(m.rules, ioc)
	m.log.Info("Loaded OpenIOC rule",
		zap.String("ioc_id", ioc.ID),
		zap.String("description", ioc.Metadata.ShortDescription),
	)

	return nil
}

// MatchFileIOC checks if a file IOC matches any loaded rules
func (m *IOCMatcher) MatchFileIOC(ioc FileIOC) []IOCMatch {
	var matches []IOCMatch

	for _, rule := range m.rules {
		if match := m.matchFileAgainstRule(ioc, rule); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// MatchNetworkIOC checks if a network IOC matches any loaded rules
func (m *IOCMatcher) MatchNetworkIOC(ioc NetworkIOC) []IOCMatch {
	var matches []IOCMatch

	for _, rule := range m.rules {
		if match := m.matchNetworkAgainstRule(ioc, rule); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// MatchProcessIOC checks if a process IOC matches any loaded rules
func (m *IOCMatcher) MatchProcessIOC(proc Process) []IOCMatch {
	var matches []IOCMatch

	for _, rule := range m.rules {
		if match := m.matchProcessAgainstRule(proc, rule); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// matchFileAgainstRule matches a file IOC against a specific rule
func (m *IOCMatcher) matchFileAgainstRule(ioc FileIOC, rule OpenIOCIndicator) *IOCMatch {
	matched := m.evaluateDefinition(rule.Definition, map[string]interface{}{
		"FileItem/FullPath":     ioc.Path,
		"FileItem/Md5sum":       ioc.MD5,
		"FileItem/Sha1sum":      ioc.SHA1,
		"FileItem/Sha256sum":    ioc.Hash,
		"FileItem/SizeInBytes":  fmt.Sprintf("%d", ioc.Size),
		"FileItem/PEInfo/DigitalSignature/SignatureExists": fmt.Sprintf("%t", ioc.Signed),
		"FileItem/PEInfo/DigitalSignature/SignatureVerified": fmt.Sprintf("%t", ioc.Signed),
	})

	if matched {
		return &IOCMatch{
			IOCID:       rule.ID,
			IOCName:     rule.Metadata.ShortDescription,
			Description: rule.Metadata.Description,
			MatchedItem: ioc.Path,
			MatchType:   "file",
			Confidence:  0.9,
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// matchNetworkAgainstRule matches a network IOC against a specific rule
func (m *IOCMatcher) matchNetworkAgainstRule(ioc NetworkIOC, rule OpenIOCIndicator) *IOCMatch {
	matched := m.evaluateDefinition(rule.Definition, map[string]interface{}{
		"PortItem/remoteIP":      ioc.RemoteAddress,
		"PortItem/remotePort":    fmt.Sprintf("%d", ioc.RemotePort),
		"PortItem/localIP":       ioc.LocalAddress,
		"PortItem/localPort":     fmt.Sprintf("%d", ioc.LocalPort),
		"PortItem/protocol":      ioc.Protocol,
		"PortItem/state":         ioc.State,
		"PortItem/process":       ioc.ProcessName,
	})

	if matched {
		return &IOCMatch{
			IOCID:       rule.ID,
			IOCName:     rule.Metadata.ShortDescription,
			Description: rule.Metadata.Description,
			MatchedItem: fmt.Sprintf("%s:%d -> %s:%d", ioc.LocalAddress, ioc.LocalPort, ioc.RemoteAddress, ioc.RemotePort),
			MatchType:   "network",
			Confidence:  0.85,
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// matchProcessAgainstRule matches a process IOC against a specific rule
func (m *IOCMatcher) matchProcessAgainstRule(proc Process, rule OpenIOCIndicator) *IOCMatch {
	matched := m.evaluateDefinition(rule.Definition, map[string]interface{}{
		"ProcessItem/name":              proc.Name,
		"ProcessItem/path":              proc.Path,
		"ProcessItem/pid":               fmt.Sprintf("%d", proc.PID),
		"ProcessItem/parentpid":         fmt.Sprintf("%d", proc.ParentPID),
		"ProcessItem/arguments":         proc.CommandLine,
		"ProcessItem/Username":          proc.User,
		"ProcessItem/HandleList/Handle": proc.Path,
	})

	if matched {
		return &IOCMatch{
			IOCID:       rule.ID,
			IOCName:     rule.Metadata.ShortDescription,
			Description: rule.Metadata.Description,
			MatchedItem: fmt.Sprintf("%s (PID: %d)", proc.Name, proc.PID),
			MatchType:   "process",
			Confidence:  0.8,
			Timestamp:   time.Now(),
		}
	}

	return nil
}

// evaluateDefinition evaluates an IOC definition against collected data
func (m *IOCMatcher) evaluateDefinition(def IOCDefinition, data map[string]interface{}) bool {
	results := []bool{}

	for _, item := range def.Items {
		result := m.evaluateItem(item, data)
		results = append(results, result)
	}

	// Apply operator
	if def.Operator == "OR" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}

	// Default AND
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

// evaluateItem evaluates a single IOC item
func (m *IOCMatcher) evaluateItem(item IOCItem, data map[string]interface{}) bool {
	results := []bool{}

	// Check nested items
	for _, nestedItem := range item.Items {
		result := m.evaluateItem(nestedItem, data)
		results = append(results, result)
	}

	// Check indicator items
	for _, indItem := range item.IndicatorItems {
		result := m.evaluateIndicatorItem(indItem, data)
		results = append(results, result)
	}

	if len(results) == 0 {
		return false
	}

	// Apply operator
	matched := false
	if item.Operator == "OR" {
		for _, r := range results {
			if r {
				matched = true
				break
			}
		}
	} else {
		// Default AND
		matched = true
		for _, r := range results {
			if !r {
				matched = false
				break
			}
		}
	}

	// Apply negation
	if item.Negate {
		matched = !matched
	}

	return matched
}

// evaluateIndicatorItem evaluates a specific indicator condition
func (m *IOCMatcher) evaluateIndicatorItem(item IndicatorItem, data map[string]interface{}) bool {
	searchPath := item.Search
	if searchPath == "" {
		searchPath = item.Document
	}

	actualValue, exists := data[searchPath]
	if !exists {
		return false
	}

	actualStr := fmt.Sprintf("%v", actualValue)
	expectedStr := item.Content.Value

	matched := false
	switch item.Condition {
	case "is":
		matched = actualStr == expectedStr
	case "contains":
		matched = strings.Contains(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "matches":
		// Regex match
		if re, err := regexp.Compile(expectedStr); err == nil {
			matched = re.MatchString(actualStr)
		}
	case "starts-with":
		matched = strings.HasPrefix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "ends-with":
		matched = strings.HasSuffix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
	case "greater-than":
		// Numeric comparison (simplified)
		matched = actualStr > expectedStr
	case "less-than":
		matched = actualStr < expectedStr
	default:
		m.log.Warn("Unknown IOC condition", zap.String("condition", item.Condition))
	}

	// Apply negation
	if item.Negate {
		matched = !matched
	}

	return matched
}

// GetRuleCount returns the number of loaded rules
func (m *IOCMatcher) GetRuleCount() int {
	return len(m.rules)
}

// ClearRules clears all loaded rules
func (m *IOCMatcher) ClearRules() {
	m.rules = []OpenIOCIndicator{}
	m.log.Info("Cleared all OpenIOC rules")
}
