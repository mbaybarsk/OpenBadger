package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/mbaybarsk/openbadger/internal/correlation"
)

var ErrAssetNotFound = errors.New("asset not found")

type Asset = correlation.Asset
type AssetIdentifier = correlation.IdentifierRecord
type AssetAddress = correlation.AddressRecord
type Sighting = correlation.Sighting

type AssetListItem struct {
	Asset                  Asset    `json:"asset"`
	Hostnames              []string `json:"hostnames,omitempty"`
	FQDN                   string   `json:"fqdn,omitempty"`
	SerialNumber           string   `json:"serial_number,omitempty"`
	SystemUUID             string   `json:"system_uuid,omitempty"`
	BIOSUUID               string   `json:"bios_uuid,omitempty"`
	SNMPEngineID           string   `json:"snmp_engine_id,omitempty"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints,omitempty"`
	MACAddresses           []string `json:"mac_addresses,omitempty"`
	IPAddresses            []string `json:"ip_addresses,omitempty"`
}

type AssetDetail struct {
	Asset       Asset             `json:"asset"`
	Identifiers []AssetIdentifier `json:"identifiers"`
	Addresses   []AssetAddress    `json:"addresses"`
	Sightings   []Sighting        `json:"sightings"`
}

type ListAssetsParams struct {
	SiteID string
	Limit  int
}

func (r *Repository) FindAssetsByIdentifiers(ctx context.Context, siteID string, identifiers []correlation.Identifier) ([]correlation.AssetSnapshot, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	identifiers = dedupeCorrelationIdentifiers(identifiers)
	if len(identifiers) == 0 {
		return nil, nil
	}

	var sql strings.Builder
	args := []any{strings.TrimSpace(siteID)}
	sql.WriteString(`
		SELECT DISTINCT a.asset_id
		FROM assets a
		JOIN asset_identifiers ai ON ai.asset_id = a.asset_id
		WHERE a.site_id = $1 AND (
	`)

	for i, identifier := range identifiers {
		if i > 0 {
			sql.WriteString(" OR ")
		}

		args = append(args, identifier.Kind, identifier.Value)
		fmt.Fprintf(&sql, "(ai.kind = $%d AND ai.value = $%d)", len(args)-1, len(args))
	}

	sql.WriteString(`
		)
		ORDER BY a.asset_id
	`)

	ids, err := queryAssetIDs(ctx, r.db, sql.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query asset identifiers: %w", err)
	}

	return r.loadAssetSnapshots(ctx, ids)
}

func (r *Repository) FindAssetsByAddresses(ctx context.Context, siteID string, addresses []correlation.Address) ([]correlation.AssetSnapshot, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	addresses = dedupeCorrelationAddresses(addresses)
	if len(addresses) == 0 {
		return nil, nil
	}

	var sql strings.Builder
	args := []any{strings.TrimSpace(siteID)}
	sql.WriteString(`
		SELECT DISTINCT a.asset_id
		FROM assets a
		JOIN asset_addresses aa ON aa.asset_id = a.asset_id
		WHERE a.site_id = $1 AND (
	`)

	for i, address := range addresses {
		if i > 0 {
			sql.WriteString(" OR ")
		}

		args = append(args, address.Type, address.Value)
		fmt.Fprintf(&sql, "(aa.address_type = $%d AND aa.value = $%d)", len(args)-1, len(args))
	}

	sql.WriteString(`
		)
		ORDER BY a.asset_id
	`)

	ids, err := queryAssetIDs(ctx, r.db, sql.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query asset addresses: %w", err)
	}

	return r.loadAssetSnapshots(ctx, ids)
}

func (r *Repository) CreateAsset(ctx context.Context, params correlation.CreateAssetParams) (correlation.Asset, error) {
	if r == nil || r.db == nil {
		return correlation.Asset{}, fmt.Errorf("repository database is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return correlation.Asset{}, fmt.Errorf("asset site id is required")
	}

	firstSeen, lastSeen, err := normalizeSeenWindow(params.FirstSeen, params.LastSeen)
	if err != nil {
		return correlation.Asset{}, err
	}

	asset := correlation.Asset{
		ID:          uuid.NewString(),
		SiteID:      siteID,
		Provisional: params.Provisional,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
	}

	err = r.db.QueryRow(ctx, `
		INSERT INTO assets (asset_id, site_id, provisional, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`, asset.ID, asset.SiteID, asset.Provisional, asset.FirstSeen, asset.LastSeen).Scan(&asset.CreatedAt, &asset.UpdatedAt)
	if err != nil {
		return correlation.Asset{}, fmt.Errorf("insert asset: %w", err)
	}

	return asset, nil
}

func (r *Repository) UpdateAsset(ctx context.Context, params correlation.UpdateAssetParams) (correlation.Asset, error) {
	if r == nil || r.db == nil {
		return correlation.Asset{}, fmt.Errorf("repository database is required")
	}

	assetID := strings.TrimSpace(params.AssetID)
	if assetID == "" {
		return correlation.Asset{}, fmt.Errorf("asset id is required")
	}

	firstSeen, lastSeen, err := normalizeSeenWindow(params.FirstSeen, params.LastSeen)
	if err != nil {
		return correlation.Asset{}, err
	}

	asset, err := scanAsset(r.db.QueryRow(ctx, `
		UPDATE assets
		SET provisional = $2,
			first_seen = LEAST(first_seen, $3),
			last_seen = GREATEST(last_seen, $4),
			updated_at = NOW()
		WHERE asset_id = $1
		RETURNING asset_id, site_id, provisional, first_seen, last_seen, created_at, updated_at
	`, assetID, params.Provisional, firstSeen, lastSeen))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return correlation.Asset{}, ErrAssetNotFound
		}

		return correlation.Asset{}, fmt.Errorf("update asset: %w", err)
	}

	return asset, nil
}

func (r *Repository) UpsertAssetIdentifiers(ctx context.Context, params correlation.UpsertAssetIdentifiersParams) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("repository database is required")
	}

	assetID := strings.TrimSpace(params.AssetID)
	if assetID == "" {
		return fmt.Errorf("asset identifier asset id is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return fmt.Errorf("asset identifier site id is required")
	}

	firstSeen, lastSeen, err := normalizeSeenWindow(params.FirstSeen, params.LastSeen)
	if err != nil {
		return err
	}

	for _, identifier := range dedupeCorrelationIdentifiers(params.Identifiers) {
		if _, err := r.db.Exec(ctx, `
			INSERT INTO asset_identifiers (asset_id, site_id, kind, value, first_seen, last_seen, last_observation_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (asset_id, kind, value)
			DO UPDATE SET
				first_seen = LEAST(asset_identifiers.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(asset_identifiers.last_seen, EXCLUDED.last_seen),
				last_observation_id = EXCLUDED.last_observation_id,
				updated_at = NOW()
		`, assetID, siteID, identifier.Kind, identifier.Value, firstSeen, lastSeen, strings.TrimSpace(params.ObservationID)); err != nil {
			return fmt.Errorf("upsert asset identifier: %w", err)
		}
	}

	return nil
}

func (r *Repository) UpsertAssetAddresses(ctx context.Context, params correlation.UpsertAssetAddressesParams) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("repository database is required")
	}

	assetID := strings.TrimSpace(params.AssetID)
	if assetID == "" {
		return fmt.Errorf("asset address asset id is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return fmt.Errorf("asset address site id is required")
	}

	firstSeen, lastSeen, err := normalizeSeenWindow(params.FirstSeen, params.LastSeen)
	if err != nil {
		return err
	}

	for _, address := range dedupeCorrelationAddresses(params.Addresses) {
		if _, err := r.db.Exec(ctx, `
			INSERT INTO asset_addresses (asset_id, site_id, address_type, value, first_seen, last_seen, last_observation_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (asset_id, address_type, value)
			DO UPDATE SET
				first_seen = LEAST(asset_addresses.first_seen, EXCLUDED.first_seen),
				last_seen = GREATEST(asset_addresses.last_seen, EXCLUDED.last_seen),
				last_observation_id = EXCLUDED.last_observation_id,
				updated_at = NOW()
		`, assetID, siteID, address.Type, address.Value, firstSeen, lastSeen, strings.TrimSpace(params.ObservationID)); err != nil {
			return fmt.Errorf("upsert asset address: %w", err)
		}
	}

	return nil
}

func (r *Repository) CreateSighting(ctx context.Context, params correlation.CreateSightingParams) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("repository database is required")
	}

	assetID := strings.TrimSpace(params.AssetID)
	if assetID == "" {
		return fmt.Errorf("sighting asset id is required")
	}

	siteID := strings.TrimSpace(params.SiteID)
	if siteID == "" {
		return fmt.Errorf("sighting site id is required")
	}

	observationID := strings.TrimSpace(params.ObservationID)
	if observationID == "" {
		return fmt.Errorf("sighting observation id is required")
	}

	if params.ObservedAt.IsZero() {
		return fmt.Errorf("sighting observed_at is required")
	}

	if _, err := r.db.Exec(ctx, `
		INSERT INTO sightings (
			sighting_id,
			asset_id,
			site_id,
			observation_id,
			job_id,
			node_id,
			observation_type,
			observation_scope,
			observed_at,
			first_seen,
			last_seen,
			confidence,
			source_protocol
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, uuid.NewString(), assetID, siteID, observationID, trimOptionalStringPointer(params.JobID), trimOptionalStringPointer(params.NodeID), strings.TrimSpace(params.ObservationType), strings.TrimSpace(params.ObservationScope), params.ObservedAt.UTC(), normalizeOptionalTime(params.FirstSeen), normalizeOptionalTime(params.LastSeen), params.Confidence, strings.TrimSpace(params.SourceProtocol)); err != nil {
		return fmt.Errorf("insert sighting: %w", err)
	}

	return nil
}

func (r *Repository) ListAssets(ctx context.Context, params ListAssetsParams) ([]AssetListItem, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("repository database is required")
	}

	var sql strings.Builder
	args := make([]any, 0, 2)
	sql.WriteString(`
		SELECT
			a.asset_id,
			a.site_id,
			a.provisional,
			a.first_seen,
			a.last_seen,
			a.created_at,
			a.updated_at,
			COALESCE((SELECT array_agg(value ORDER BY value) FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'hostname'), ARRAY[]::TEXT[]),
			COALESCE((SELECT value FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'fqdn' ORDER BY value LIMIT 1), ''),
			COALESCE((SELECT value FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'serial_number' ORDER BY value LIMIT 1), ''),
			COALESCE((SELECT value FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'system_uuid' ORDER BY value LIMIT 1), ''),
			COALESCE((SELECT value FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'bios_uuid' ORDER BY value LIMIT 1), ''),
			COALESCE((SELECT value FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'snmp_engine_id' ORDER BY value LIMIT 1), ''),
			COALESCE((SELECT array_agg(value ORDER BY value) FROM asset_identifiers WHERE asset_id = a.asset_id AND kind = 'ssh_host_key_fingerprint'), ARRAY[]::TEXT[]),
			COALESCE((SELECT array_agg(value ORDER BY value) FROM asset_addresses WHERE asset_id = a.asset_id AND address_type = 'mac'), ARRAY[]::TEXT[]),
			COALESCE((SELECT array_agg(value ORDER BY value) FROM asset_addresses WHERE asset_id = a.asset_id AND address_type = 'ip'), ARRAY[]::TEXT[])
		FROM assets a
	`)

	if siteID := strings.TrimSpace(params.SiteID); siteID != "" {
		args = append(args, siteID)
		fmt.Fprintf(&sql, "WHERE a.site_id = $%d\n", len(args))
	}

	args = append(args, normalizeAssetLimit(params.Limit))
	fmt.Fprintf(&sql, "ORDER BY a.last_seen DESC, a.created_at DESC\nLIMIT $%d", len(args))

	rows, err := r.db.Query(ctx, sql.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	items := make([]AssetListItem, 0)
	for rows.Next() {
		var item AssetListItem
		if err := rows.Scan(
			&item.Asset.ID,
			&item.Asset.SiteID,
			&item.Asset.Provisional,
			&item.Asset.FirstSeen,
			&item.Asset.LastSeen,
			&item.Asset.CreatedAt,
			&item.Asset.UpdatedAt,
			&item.Hostnames,
			&item.FQDN,
			&item.SerialNumber,
			&item.SystemUUID,
			&item.BIOSUUID,
			&item.SNMPEngineID,
			&item.SSHHostKeyFingerprints,
			&item.MACAddresses,
			&item.IPAddresses,
		); err != nil {
			return nil, fmt.Errorf("scan asset list item: %w", err)
		}

		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assets: %w", err)
	}

	return items, nil
}

func (r *Repository) GetAssetDetail(ctx context.Context, assetID string) (AssetDetail, error) {
	if r == nil || r.db == nil {
		return AssetDetail{}, fmt.Errorf("repository database is required")
	}

	asset, err := r.getAsset(ctx, assetID)
	if err != nil {
		return AssetDetail{}, err
	}

	identifiers, err := r.listAssetIdentifiers(ctx, asset.ID)
	if err != nil {
		return AssetDetail{}, err
	}

	addresses, err := r.listAssetAddresses(ctx, asset.ID)
	if err != nil {
		return AssetDetail{}, err
	}

	sightings, err := r.listAssetSightings(ctx, asset.ID)
	if err != nil {
		return AssetDetail{}, err
	}

	return AssetDetail{
		Asset:       asset,
		Identifiers: identifiers,
		Addresses:   addresses,
		Sightings:   sightings,
	}, nil
}

func (r *Repository) loadAssetSnapshots(ctx context.Context, ids []string) ([]correlation.AssetSnapshot, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	ids = dedupeAssetIDs(ids)
	snapshots := make([]correlation.AssetSnapshot, 0, len(ids))
	for _, assetID := range ids {
		asset, err := r.getAsset(ctx, assetID)
		if err != nil {
			return nil, err
		}

		identifiers, err := r.listAssetIdentifiers(ctx, assetID)
		if err != nil {
			return nil, err
		}

		addresses, err := r.listAssetAddresses(ctx, assetID)
		if err != nil {
			return nil, err
		}

		snapshots = append(snapshots, correlation.AssetSnapshot{
			Asset:       asset,
			Identifiers: identifiers,
			Addresses:   addresses,
		})
	}

	return snapshots, nil
}

func (r *Repository) getAsset(ctx context.Context, assetID string) (Asset, error) {
	asset, err := scanAsset(r.db.QueryRow(ctx, `
		SELECT asset_id, site_id, provisional, first_seen, last_seen, created_at, updated_at
		FROM assets
		WHERE asset_id = $1
	`, strings.TrimSpace(assetID)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Asset{}, ErrAssetNotFound
		}

		return Asset{}, fmt.Errorf("select asset: %w", err)
	}

	return asset, nil
}

func (r *Repository) listAssetIdentifiers(ctx context.Context, assetID string) ([]AssetIdentifier, error) {
	rows, err := r.db.Query(ctx, `
		SELECT asset_id, kind, value, first_seen, last_seen
		FROM asset_identifiers
		WHERE asset_id = $1
		ORDER BY kind, value
	`, strings.TrimSpace(assetID))
	if err != nil {
		return nil, fmt.Errorf("list asset identifiers: %w", err)
	}
	defer rows.Close()

	identifiers := make([]AssetIdentifier, 0)
	for rows.Next() {
		var identifier AssetIdentifier
		if err := rows.Scan(&identifier.AssetID, &identifier.Kind, &identifier.Value, &identifier.FirstSeen, &identifier.LastSeen); err != nil {
			return nil, fmt.Errorf("scan asset identifier: %w", err)
		}

		identifiers = append(identifiers, identifier)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset identifiers: %w", err)
	}

	return identifiers, nil
}

func (r *Repository) listAssetAddresses(ctx context.Context, assetID string) ([]AssetAddress, error) {
	rows, err := r.db.Query(ctx, `
		SELECT asset_id, address_type, value, first_seen, last_seen
		FROM asset_addresses
		WHERE asset_id = $1
		ORDER BY address_type, value
	`, strings.TrimSpace(assetID))
	if err != nil {
		return nil, fmt.Errorf("list asset addresses: %w", err)
	}
	defer rows.Close()

	addresses := make([]AssetAddress, 0)
	for rows.Next() {
		var address AssetAddress
		if err := rows.Scan(&address.AssetID, &address.Type, &address.Value, &address.FirstSeen, &address.LastSeen); err != nil {
			return nil, fmt.Errorf("scan asset address: %w", err)
		}

		addresses = append(addresses, address)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset addresses: %w", err)
	}

	return addresses, nil
}

func (r *Repository) listAssetSightings(ctx context.Context, assetID string) ([]Sighting, error) {
	rows, err := r.db.Query(ctx, `
		SELECT sighting_id, asset_id, site_id, observation_id, observation_type, observation_scope, job_id, node_id, observed_at, first_seen, last_seen, confidence, source_protocol, created_at
		FROM sightings
		WHERE asset_id = $1
		ORDER BY observed_at DESC, created_at DESC
	`, strings.TrimSpace(assetID))
	if err != nil {
		return nil, fmt.Errorf("list asset sightings: %w", err)
	}
	defer rows.Close()

	sightings := make([]Sighting, 0)
	for rows.Next() {
		var sighting Sighting
		if err := rows.Scan(
			&sighting.ID,
			&sighting.AssetID,
			&sighting.SiteID,
			&sighting.ObservationID,
			&sighting.ObservationType,
			&sighting.ObservationScope,
			&sighting.JobID,
			&sighting.NodeID,
			&sighting.ObservedAt,
			&sighting.FirstSeen,
			&sighting.LastSeen,
			&sighting.Confidence,
			&sighting.SourceProtocol,
			&sighting.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan asset sighting: %w", err)
		}

		sightings = append(sightings, sighting)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset sightings: %w", err)
	}

	return sightings, nil
}

func queryAssetIDs(ctx context.Context, db DBTX, sql string, args ...any) ([]string, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make([]string, 0)
	for rows.Next() {
		var assetID string
		if err := rows.Scan(&assetID); err != nil {
			return nil, fmt.Errorf("scan asset id: %w", err)
		}

		ids = append(ids, assetID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset ids: %w", err)
	}

	return ids, nil
}

func scanAsset(row rowScanner) (Asset, error) {
	var asset Asset
	err := row.Scan(&asset.ID, &asset.SiteID, &asset.Provisional, &asset.FirstSeen, &asset.LastSeen, &asset.CreatedAt, &asset.UpdatedAt)
	if err != nil {
		return Asset{}, err
	}

	return asset, nil
}

func dedupeAssetIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}

		seen[id] = true
		result = append(result, id)
	}

	sort.Strings(result)
	return result
}

func dedupeCorrelationIdentifiers(values []correlation.Identifier) []correlation.Identifier {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]correlation.Identifier, 0, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value.Kind) + "\x00" + strings.TrimSpace(value.Value)
		if key == "\x00" || seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, correlation.Identifier{Kind: strings.TrimSpace(value.Kind), Value: strings.TrimSpace(value.Value)})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].Value < result[j].Value
	})

	return result
}

func dedupeCorrelationAddresses(values []correlation.Address) []correlation.Address {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]correlation.Address, 0, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value.Type) + "\x00" + strings.TrimSpace(value.Value)
		if key == "\x00" || seen[key] {
			continue
		}

		seen[key] = true
		result = append(result, correlation.Address{Type: strings.TrimSpace(value.Type), Value: strings.TrimSpace(value.Value)})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].Value < result[j].Value
	})

	return result
}

func normalizeSeenWindow(firstSeen time.Time, lastSeen time.Time) (time.Time, time.Time, error) {
	if firstSeen.IsZero() && lastSeen.IsZero() {
		return time.Time{}, time.Time{}, fmt.Errorf("asset seen_at is required")
	}

	if firstSeen.IsZero() {
		firstSeen = lastSeen
	}
	if lastSeen.IsZero() {
		lastSeen = firstSeen
	}

	firstSeen = firstSeen.UTC()
	lastSeen = lastSeen.UTC()
	if firstSeen.After(lastSeen) {
		firstSeen = lastSeen
	}

	return firstSeen, lastSeen, nil
}

func normalizeOptionalTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}

	copy := value.UTC()
	return &copy
}

func normalizeAssetLimit(limit int) int {
	if limit <= 0 {
		return 100
	}

	if limit > 500 {
		return 500
	}

	return limit
}
