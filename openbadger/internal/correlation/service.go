package correlation

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/mbaybarsk/openbadger/internal/observations"
)

const (
	IdentifierKindHostname              = "hostname"
	IdentifierKindFQDN                  = "fqdn"
	IdentifierKindSerialNumber          = "serial_number"
	IdentifierKindSystemUUID            = "system_uuid"
	IdentifierKindBIOSUUID              = "bios_uuid"
	IdentifierKindSNMPEngineID          = "snmp_engine_id"
	IdentifierKindSSHHostKeyFingerprint = "ssh_host_key_fingerprint"

	AddressTypeIP  = "ip"
	AddressTypeMAC = "mac"
)

type Identifier struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Address struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Asset struct {
	ID          string    `json:"asset_id"`
	SiteID      string    `json:"site_id"`
	Provisional bool      `json:"provisional"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type IdentifierRecord struct {
	AssetID   string    `json:"asset_id"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type AddressRecord struct {
	AssetID   string    `json:"asset_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Sighting struct {
	ID               string     `json:"sighting_id"`
	AssetID          string     `json:"asset_id"`
	SiteID           string     `json:"site_id"`
	ObservationID    string     `json:"observation_id"`
	ObservationType  string     `json:"observation_type"`
	ObservationScope string     `json:"observation_scope"`
	JobID            *string    `json:"job_id,omitempty"`
	NodeID           *string    `json:"node_id,omitempty"`
	ObservedAt       time.Time  `json:"observed_at"`
	FirstSeen        *time.Time `json:"first_seen,omitempty"`
	LastSeen         *time.Time `json:"last_seen,omitempty"`
	Confidence       float64    `json:"confidence"`
	SourceProtocol   string     `json:"source_protocol,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type AssetSnapshot struct {
	Asset       Asset              `json:"asset"`
	Identifiers []IdentifierRecord `json:"identifiers"`
	Addresses   []AddressRecord    `json:"addresses"`
}

type CreateAssetParams struct {
	SiteID      string
	Provisional bool
	FirstSeen   time.Time
	LastSeen    time.Time
}

type UpdateAssetParams struct {
	AssetID     string
	Provisional bool
	FirstSeen   time.Time
	LastSeen    time.Time
}

type UpsertAssetIdentifiersParams struct {
	AssetID       string
	SiteID        string
	ObservationID string
	FirstSeen     time.Time
	LastSeen      time.Time
	Identifiers   []Identifier
}

type UpsertAssetAddressesParams struct {
	AssetID       string
	SiteID        string
	ObservationID string
	FirstSeen     time.Time
	LastSeen      time.Time
	Addresses     []Address
}

type CreateSightingParams struct {
	AssetID          string
	SiteID           string
	ObservationID    string
	ObservationType  string
	ObservationScope string
	JobID            *string
	NodeID           *string
	ObservedAt       time.Time
	FirstSeen        *time.Time
	LastSeen         *time.Time
	Confidence       float64
	SourceProtocol   string
}

type Store interface {
	FindAssetsByIdentifiers(ctx context.Context, siteID string, identifiers []Identifier) ([]AssetSnapshot, error)
	FindAssetsByAddresses(ctx context.Context, siteID string, addresses []Address) ([]AssetSnapshot, error)
	CreateAsset(ctx context.Context, params CreateAssetParams) (Asset, error)
	UpdateAsset(ctx context.Context, params UpdateAssetParams) (Asset, error)
	UpsertAssetIdentifiers(ctx context.Context, params UpsertAssetIdentifiersParams) error
	UpsertAssetAddresses(ctx context.Context, params UpsertAssetAddressesParams) error
	CreateSighting(ctx context.Context, params CreateSightingParams) error
}

type Service struct {
	store Store
}

type evidence struct {
	StrongIdentifiers []Identifier
	MediumIdentifiers []Identifier
	AllIdentifiers    []Identifier
	AllAddresses      []Address
	WeakAddresses     []Address
	FirstSeen         time.Time
	LastSeen          time.Time
	SightingFirstSeen *time.Time
	SightingLastSeen  *time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Correlate(ctx context.Context, observation observations.Observation) (Asset, error) {
	if s == nil || s.store == nil {
		return Asset{}, fmt.Errorf("correlation service is unavailable")
	}

	if strings.EqualFold(strings.TrimSpace(observation.Scope), "relationship") {
		return Asset{}, nil
	}

	evidence := extractEvidence(observation)
	if len(evidence.AllIdentifiers) == 0 && len(evidence.AllAddresses) == 0 {
		return Asset{}, nil
	}

	siteID := strings.TrimSpace(observation.SiteID)
	if siteID == "" {
		return Asset{}, fmt.Errorf("observation site_id is required")
	}

	strongMatches, err := s.store.FindAssetsByIdentifiers(ctx, siteID, evidence.StrongIdentifiers)
	if err != nil {
		return Asset{}, fmt.Errorf("find strong asset matches: %w", err)
	}

	selected := selectStrongMatch(strongMatches, evidence.StrongIdentifiers)
	if selected == nil {
		candidateMatches, err := s.findCandidateMatches(ctx, siteID, evidence)
		if err != nil {
			return Asset{}, err
		}

		if len(candidateMatches) == 1 && !hasStrongConflict(candidateMatches[0], evidence.StrongIdentifiers) {
			selected = &candidateMatches[0]
		}
	}

	blockedStrong := blockedStrongIdentifiers(strongMatches, selected)
	identifiersToStore := filterBlockedIdentifiers(evidence.AllIdentifiers, blockedStrong)
	strongToStore := filterStrongIdentifiers(identifiersToStore)
	provisional := len(strongToStore) == 0

	asset, err := s.upsertAsset(ctx, selected, observation, evidence, provisional)
	if err != nil {
		return Asset{}, err
	}

	if len(identifiersToStore) > 0 {
		if err := s.store.UpsertAssetIdentifiers(ctx, UpsertAssetIdentifiersParams{
			AssetID:       asset.ID,
			SiteID:        asset.SiteID,
			ObservationID: strings.TrimSpace(observation.ObservationID),
			FirstSeen:     evidence.FirstSeen,
			LastSeen:      evidence.LastSeen,
			Identifiers:   identifiersToStore,
		}); err != nil {
			return Asset{}, fmt.Errorf("upsert asset identifiers: %w", err)
		}
	}

	if len(evidence.AllAddresses) > 0 {
		if err := s.store.UpsertAssetAddresses(ctx, UpsertAssetAddressesParams{
			AssetID:       asset.ID,
			SiteID:        asset.SiteID,
			ObservationID: strings.TrimSpace(observation.ObservationID),
			FirstSeen:     evidence.FirstSeen,
			LastSeen:      evidence.LastSeen,
			Addresses:     evidence.AllAddresses,
		}); err != nil {
			return Asset{}, fmt.Errorf("upsert asset addresses: %w", err)
		}
	}

	if err := s.store.CreateSighting(ctx, CreateSightingParams{
		AssetID:          asset.ID,
		SiteID:           asset.SiteID,
		ObservationID:    strings.TrimSpace(observation.ObservationID),
		ObservationType:  strings.TrimSpace(observation.Type),
		ObservationScope: strings.TrimSpace(observation.Scope),
		JobID:            optionalStringPointer(observation.JobID),
		NodeID:           observationNodeID(observation),
		ObservedAt:       observation.ObservedAt.UTC(),
		FirstSeen:        evidence.SightingFirstSeen,
		LastSeen:         evidence.SightingLastSeen,
		Confidence:       observationConfidence(observation),
		SourceProtocol:   observationSourceProtocol(observation),
	}); err != nil {
		return Asset{}, fmt.Errorf("create sighting: %w", err)
	}

	return asset, nil
}

func (s *Service) findCandidateMatches(ctx context.Context, siteID string, evidence evidence) ([]AssetSnapshot, error) {
	combined := make(map[string]AssetSnapshot)

	identifierMatches, err := s.store.FindAssetsByIdentifiers(ctx, siteID, evidence.MediumIdentifiers)
	if err != nil {
		return nil, fmt.Errorf("find identifier asset matches: %w", err)
	}
	for _, match := range identifierMatches {
		combined[match.Asset.ID] = match
	}

	addressMatches, err := s.store.FindAssetsByAddresses(ctx, siteID, append([]Address(nil), evidence.AllAddresses...))
	if err != nil {
		return nil, fmt.Errorf("find address asset matches: %w", err)
	}
	for _, match := range addressMatches {
		combined[match.Asset.ID] = match
	}

	ordered := make([]AssetSnapshot, 0, len(combined))
	for _, match := range combined {
		ordered = append(ordered, match)
	}

	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Asset.Provisional != ordered[j].Asset.Provisional {
			return ordered[i].Asset.Provisional && !ordered[j].Asset.Provisional
		}

		if !ordered[i].Asset.LastSeen.Equal(ordered[j].Asset.LastSeen) {
			return ordered[i].Asset.LastSeen.After(ordered[j].Asset.LastSeen)
		}

		return ordered[i].Asset.ID < ordered[j].Asset.ID
	})

	return ordered, nil
}

func (s *Service) upsertAsset(ctx context.Context, selected *AssetSnapshot, observation observations.Observation, evidence evidence, provisional bool) (Asset, error) {
	if selected == nil {
		asset, err := s.store.CreateAsset(ctx, CreateAssetParams{
			SiteID:      strings.TrimSpace(observation.SiteID),
			Provisional: provisional,
			FirstSeen:   evidence.FirstSeen,
			LastSeen:    evidence.LastSeen,
		})
		if err != nil {
			return Asset{}, fmt.Errorf("create asset: %w", err)
		}

		return asset, nil
	}

	asset, err := s.store.UpdateAsset(ctx, UpdateAssetParams{
		AssetID:     selected.Asset.ID,
		Provisional: selected.Asset.Provisional && provisional,
		FirstSeen:   evidence.FirstSeen,
		LastSeen:    evidence.LastSeen,
	})
	if err != nil {
		return Asset{}, fmt.Errorf("update asset: %w", err)
	}

	return asset, nil
}

func selectStrongMatch(matches []AssetSnapshot, strongIdentifiers []Identifier) *AssetSnapshot {
	if len(strongIdentifiers) == 0 {
		return nil
	}

	unique := make(map[string]AssetSnapshot)
	for _, match := range matches {
		unique[match.Asset.ID] = match
	}

	if len(unique) != 1 {
		return nil
	}

	for _, match := range unique {
		if hasStrongConflict(match, strongIdentifiers) {
			return nil
		}

		copy := match
		return &copy
	}

	return nil
}

func blockedStrongIdentifiers(matches []AssetSnapshot, selected *AssetSnapshot) map[string]bool {
	blocked := make(map[string]bool)
	selectedID := ""
	if selected != nil {
		selectedID = selected.Asset.ID
	}

	for _, match := range matches {
		if match.Asset.ID == selectedID {
			continue
		}

		for _, identifier := range match.Identifiers {
			if !isStrongKind(identifier.Kind) {
				continue
			}

			blocked[identifier.Kind+"\x00"+identifier.Value] = true
		}
	}

	return blocked
}

func filterBlockedIdentifiers(identifiers []Identifier, blocked map[string]bool) []Identifier {
	filtered := make([]Identifier, 0, len(identifiers))
	for _, identifier := range identifiers {
		if isStrongKind(identifier.Kind) && blocked[identifier.Kind+"\x00"+identifier.Value] {
			continue
		}

		filtered = append(filtered, identifier)
	}

	return filtered
}

func filterStrongIdentifiers(identifiers []Identifier) []Identifier {
	strong := make([]Identifier, 0, len(identifiers))
	for _, identifier := range identifiers {
		if isStrongKind(identifier.Kind) {
			strong = append(strong, identifier)
		}
	}

	return strong
}

func hasStrongConflict(snapshot AssetSnapshot, incoming []Identifier) bool {
	if len(incoming) == 0 {
		return false
	}

	existing := make(map[string][]string)
	for _, identifier := range snapshot.Identifiers {
		if !isStrongKind(identifier.Kind) {
			continue
		}

		existing[identifier.Kind] = append(existing[identifier.Kind], identifier.Value)
	}

	incomingByKind := make(map[string][]string)
	for _, identifier := range incoming {
		if !isStrongKind(identifier.Kind) {
			continue
		}

		incomingByKind[identifier.Kind] = append(incomingByKind[identifier.Kind], identifier.Value)
	}

	for kind, incomingValues := range incomingByKind {
		existingValues := existing[kind]
		if len(existingValues) == 0 {
			continue
		}

		if kind == IdentifierKindSSHHostKeyFingerprint {
			if !sharesAny(existingValues, incomingValues) {
				return true
			}
			continue
		}

		for _, value := range incomingValues {
			if !containsString(existingValues, value) {
				return true
			}
		}
	}

	return false
}

func sharesAny(left []string, right []string) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if leftValue == rightValue {
				return true
			}
		}
	}

	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func extractEvidence(observation observations.Observation) evidence {
	identifiers := make([]Identifier, 0)
	strong := make([]Identifier, 0)
	medium := make([]Identifier, 0)
	addresses := make([]Address, 0)
	weak := make([]Address, 0)

	if observation.Identifiers != nil {
		for _, hostname := range observation.Identifiers.Hostnames {
			if value := normalizeIdentifierValue(IdentifierKindHostname, hostname); value != "" {
				identifier := Identifier{Kind: IdentifierKindHostname, Value: value}
				identifiers = append(identifiers, identifier)
				medium = append(medium, identifier)
			}
		}

		if value := normalizeIdentifierValue(IdentifierKindFQDN, observation.Identifiers.FQDN); value != "" {
			identifier := Identifier{Kind: IdentifierKindFQDN, Value: value}
			identifiers = append(identifiers, identifier)
			medium = append(medium, identifier)
		}

		strong = appendNormalizedIdentifier(strong, IdentifierKindSerialNumber, observation.Identifiers.SerialNumber)
		strong = appendNormalizedIdentifier(strong, IdentifierKindSystemUUID, observation.Identifiers.SystemUUID)
		strong = appendNormalizedIdentifier(strong, IdentifierKindBIOSUUID, observation.Identifiers.BIOSUUID)
		strong = appendNormalizedIdentifier(strong, IdentifierKindSNMPEngineID, observation.Identifiers.SNMPEngineID)

		for _, fingerprint := range observation.Identifiers.SSHHostKeyFingerprints {
			strong = appendNormalizedIdentifier(strong, IdentifierKindSSHHostKeyFingerprint, fingerprint)
		}

		for _, macAddress := range observation.Identifiers.MACAddresses {
			if value := normalizeAddressValue(AddressTypeMAC, macAddress); value != "" {
				address := Address{Type: AddressTypeMAC, Value: value}
				addresses = append(addresses, address)
			}
		}
	}

	identifiers = append(identifiers, strong...)

	if observation.Addresses != nil {
		for _, ipAddress := range observation.Addresses.IPAddresses {
			if value := normalizeAddressValue(AddressTypeIP, ipAddress); value != "" {
				address := Address{Type: AddressTypeIP, Value: value}
				addresses = append(addresses, address)
				weak = append(weak, address)
			}
		}
	}

	if observation.Target != nil {
		if value := normalizeAddressValue(AddressTypeIP, observation.Target.IP); value != "" {
			address := Address{Type: AddressTypeIP, Value: value}
			addresses = append(addresses, address)
			weak = append(weak, address)
		}

		if value := normalizeIdentifierValue(IdentifierKindHostname, observation.Target.Hostname); value != "" {
			identifier := Identifier{Kind: IdentifierKindHostname, Value: value}
			identifiers = append(identifiers, identifier)
			medium = append(medium, identifier)
		}
	}

	identifiers = dedupeIdentifiers(identifiers)
	strong = dedupeIdentifiers(strong)
	medium = dedupeIdentifiers(medium)
	addresses = dedupeAddresses(addresses)
	weak = dedupeAddresses(weak)

	firstSeen, lastSeen, sightingFirstSeen, sightingLastSeen := observationWindow(observation)

	return evidence{
		StrongIdentifiers: strong,
		MediumIdentifiers: medium,
		AllIdentifiers:    identifiers,
		AllAddresses:      addresses,
		WeakAddresses:     weak,
		FirstSeen:         firstSeen,
		LastSeen:          lastSeen,
		SightingFirstSeen: sightingFirstSeen,
		SightingLastSeen:  sightingLastSeen,
	}
}

func appendNormalizedIdentifier(target []Identifier, kind string, value string) []Identifier {
	if normalized := normalizeIdentifierValue(kind, value); normalized != "" {
		return append(target, Identifier{Kind: kind, Value: normalized})
	}

	return target
}

func observationWindow(observation observations.Observation) (time.Time, time.Time, *time.Time, *time.Time) {
	observedAt := observation.ObservedAt.UTC()
	firstSeen := observedAt
	lastSeen := observedAt
	var firstSeenPtr *time.Time
	var lastSeenPtr *time.Time

	if observation.Evidence != nil {
		if observation.Evidence.FirstSeen != nil && !observation.Evidence.FirstSeen.IsZero() {
			value := observation.Evidence.FirstSeen.UTC()
			firstSeen = value
			firstSeenPtr = &value
		}

		if observation.Evidence.LastSeen != nil && !observation.Evidence.LastSeen.IsZero() {
			value := observation.Evidence.LastSeen.UTC()
			lastSeen = value
			lastSeenPtr = &value
		}
	}

	if firstSeen.After(lastSeen) {
		firstSeen = lastSeen
		firstSeenPtr = &firstSeen
	}

	if firstSeenPtr == nil && !firstSeen.Equal(observedAt) {
		value := firstSeen
		firstSeenPtr = &value
	}

	if lastSeenPtr == nil && !lastSeen.Equal(observedAt) {
		value := lastSeen
		lastSeenPtr = &value
	}

	return firstSeen, lastSeen, firstSeenPtr, lastSeenPtr
}

func normalizeIdentifierValue(kind string, value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}

	switch kind {
	case IdentifierKindSystemUUID, IdentifierKindBIOSUUID:
		if parsed, err := parseUUIDLike(value); err == nil {
			return parsed
		}
	}

	return value
}

func normalizeAddressValue(addressType string, value string) string {
	switch addressType {
	case AddressTypeIP:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || !addr.IsValid() {
			return ""
		}

		return addr.String()
	case AddressTypeMAC:
		parsed, err := net.ParseMAC(strings.TrimSpace(value))
		if err != nil {
			return ""
		}

		return strings.ToLower(parsed.String())
	default:
		return strings.TrimSpace(strings.ToLower(value))
	}
}

func parseUUIDLike(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) == 32 && !strings.Contains(value, "-") {
		value = value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
	}

	parsed, err := netip.ParseAddr(value)
	if err == nil && parsed.IsValid() {
		return "", fmt.Errorf("uuid value is an ip address")
	}

	if len(value) != 36 {
		return "", fmt.Errorf("uuid value %q is invalid", value)
	}

	for i, ch := range value {
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return "", fmt.Errorf("uuid value %q is invalid", value)
			}
		default:
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return "", fmt.Errorf("uuid value %q is invalid", value)
			}
		}
	}

	return value, nil
}

func dedupeIdentifiers(values []Identifier) []Identifier {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]Identifier, 0, len(values))
	for _, value := range values {
		if value.Kind == "" || value.Value == "" {
			continue
		}

		key := value.Kind + "\x00" + value.Value
		if seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, value)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}

		return result[i].Value < result[j].Value
	})

	return result
}

func dedupeAddresses(values []Address) []Address {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]Address, 0, len(values))
	for _, value := range values {
		if value.Type == "" || value.Value == "" {
			continue
		}

		key := value.Type + "\x00" + value.Value
		if seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, value)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}

		return result[i].Value < result[j].Value
	})

	return result
}

func isStrongKind(kind string) bool {
	switch strings.TrimSpace(kind) {
	case IdentifierKindSerialNumber, IdentifierKindSystemUUID, IdentifierKindBIOSUUID, IdentifierKindSNMPEngineID, IdentifierKindSSHHostKeyFingerprint:
		return true
	default:
		return false
	}
}

func optionalStringPointer(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	return &trimmed
}

func observationNodeID(observation observations.Observation) *string {
	if observation.Emitter == nil {
		return nil
	}

	return optionalStringPointer(observation.Emitter.ID)
}

func observationConfidence(observation observations.Observation) float64 {
	if observation.Evidence == nil {
		return 0
	}

	return observation.Evidence.Confidence
}

func observationSourceProtocol(observation observations.Observation) string {
	if observation.Evidence == nil {
		return ""
	}

	return strings.TrimSpace(strings.ToLower(observation.Evidence.SourceProtocol))
}
