package observer

import (
	"context"
	"fmt"

	"github.com/danielmichaels/gecko/internal/dnsrecords"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
)

// TypeResult carries one record type's observed entries and whether the
// resolution was authoritative (so deletions can be gated).
type TypeResult struct {
	Entries       []string
	Authoritative bool
}

// Resolved is the full set of a scan's observed records, one entry per type.
type Resolved struct {
	A      TypeResult
	AAAA   TypeResult
	CNAME  TypeResult
	MX     TypeResult
	TXT    TypeResult
	NS     TypeResult
	SOA    TypeResult
	PTR    TypeResult
	CAA    TypeResult
	SRV    TypeResult
	DNSKEY TypeResult
	DS     TypeResult
	RRSIG  TypeResult
}

// RecordAll syncs every DNS record type for one scan through the recorder. The
// caller runs it inside a single transaction so the whole scan's projection
// changes and observations commit atomically.
func (r *Recorder) RecordAll(ctx context.Context, ident DomainIdentity, res Resolved) error {
	steps := []func(context.Context, DomainIdentity) error{
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordA(ctx, id, res.A.Entries, res.A.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordAAAA(ctx, id, res.AAAA.Entries, res.AAAA.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordCNAME(ctx, id, res.CNAME.Entries, res.CNAME.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordTXT(ctx, id, res.TXT.Entries, res.TXT.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordNS(ctx, id, res.NS.Entries, res.NS.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordPTR(ctx, id, res.PTR.Entries, res.PTR.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordMX(ctx, id, res.MX.Entries, res.MX.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordSRV(ctx, id, res.SRV.Entries, res.SRV.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordSOA(ctx, id, res.SOA.Entries, res.SOA.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordCAA(ctx, id, res.CAA.Entries, res.CAA.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordDNSKEY(ctx, id, res.DNSKEY.Entries, res.DNSKEY.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordDS(ctx, id, res.DS.Entries, res.DS.Authoritative)
		},
		func(ctx context.Context, id DomainIdentity) error {
			return r.RecordRRSIG(ctx, id, res.RRSIG.Entries, res.RRSIG.Authoritative)
		},
	}
	for _, step := range steps {
		if err := step(ctx, ident); err != nil {
			return err
		}
	}
	return nil
}

// recordValueKeyed handles types whose natural key is the single stored value
// (A, AAAA, CNAME, TXT, NS, PTR): no mutable payload behind the key, so changes
// are only ever created/deleted.
func (r *Recorder) recordValueKeyed(
	ctx context.Context,
	ident DomainIdentity,
	entityType, field string,
	observedValues, currentValues []string,
	authoritative bool,
	upsert func(context.Context, string) error,
	del func(context.Context, string) error,
) error {
	obs := make(map[string]observedEntity, len(observedValues))
	for _, v := range observedValues {
		obs[v] = observedEntity{
			payload: PayloadJSON(map[string]any{field: v}),
			upsert:  func(ctx context.Context) error { return upsert(ctx, v) },
		}
	}
	cur := make(map[string]currentEntity, len(currentValues))
	for _, v := range currentValues {
		cur[v] = currentEntity{
			payload: PayloadJSON(map[string]any{field: v}),
			delete:  func(ctx context.Context) error { return del(ctx, v) },
		}
	}
	return r.sync(ctx, ident, entityType, obs, cur, authoritative)
}

func (r *Recorder) RecordA(
	ctx context.Context,
	ident DomainIdentity,
	ips []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetAByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load A records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Ipv4Address
	}
	return r.recordValueKeyed(ctx, ident, EntityARecord, "ipv4_address", ips, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreateA(ctx, store.RecordsCreateAParams{DomainID: domainID, Ipv4Address: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeleteA(ctx, store.RecordsDeleteAParams{DomainID: domainID, Ipv4Address: v})
		})
}

func (r *Recorder) RecordAAAA(
	ctx context.Context,
	ident DomainIdentity,
	ips []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetAAAAByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load AAAA records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Ipv6Address
	}
	return r.recordValueKeyed(ctx, ident, EntityAAAARecord, "ipv6_address", ips, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreateAAAA(ctx, store.RecordsCreateAAAAParams{DomainID: domainID, Ipv6Address: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeleteAAAA(ctx, store.RecordsDeleteAAAAParams{DomainID: domainID, Ipv6Address: v})
		})
}

func (r *Recorder) RecordCNAME(
	ctx context.Context,
	ident DomainIdentity,
	targets []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetCNAMEByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load CNAME records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Target
	}
	return r.recordValueKeyed(ctx, ident, EntityCNAMERecord, "target", targets, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreateCNAME(ctx, store.RecordsCreateCNAMEParams{DomainID: domainID, Target: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeleteCNAME(ctx, store.RecordsDeleteCNAMEParams{DomainID: domainID, Target: v})
		})
}

func (r *Recorder) RecordTXT(
	ctx context.Context,
	ident DomainIdentity,
	values []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetTXTByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load TXT records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Value
	}
	return r.recordValueKeyed(ctx, ident, EntityTXTRecord, "value", values, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreateTXT(ctx, store.RecordsCreateTXTParams{DomainID: domainID, Value: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeleteTXT(ctx, store.RecordsDeleteTXTParams{DomainID: domainID, Value: v})
		})
}

func (r *Recorder) RecordNS(
	ctx context.Context,
	ident DomainIdentity,
	nameservers []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetNSByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load NS records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Nameserver
	}
	return r.recordValueKeyed(ctx, ident, EntityNSRecord, "nameserver", nameservers, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreateNS(ctx, store.RecordsCreateNSParams{DomainID: domainID, Nameserver: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeleteNS(ctx, store.RecordsDeleteNSParams{DomainID: domainID, Nameserver: v})
		})
}

func (r *Recorder) RecordPTR(
	ctx context.Context,
	ident DomainIdentity,
	targets []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	rows, err := r.q.RecordsGetPTRByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load PTR records: %w", err)
	}
	current := make([]string, len(rows))
	for i, row := range rows {
		current[i] = row.Target
	}
	return r.recordValueKeyed(ctx, ident, EntityPTRRecord, "target", targets, current, authoritative,
		func(ctx context.Context, v string) error {
			_, e := r.q.RecordsCreatePTR(ctx, store.RecordsCreatePTRParams{DomainID: domainID, Target: v})
			return e
		},
		func(ctx context.Context, v string) error {
			return r.q.RecordsDeletePTR(ctx, store.RecordsDeletePTRParams{DomainID: domainID, Target: v})
		})
}

func (r *Recorder) RecordMX(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseMX(ident.DomainName, entry)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d|%s", v.Preference, v.Target)
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{"preference": v.Preference, "target": v.Target}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateMX(ctx, store.RecordsCreateMXParams{
					DomainID: domainID, Preference: int32(v.Preference), Target: v.Target,
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetMXByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load MX records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%d|%s", row.Preference, row.Target)
		cur[key] = currentEntity{
			payload: PayloadJSON(map[string]any{"preference": int(row.Preference), "target": row.Target}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteMX(ctx, store.RecordsDeleteMXParams{
					DomainID: domainID, Preference: row.Preference, Target: row.Target,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntityMXRecord, obs, cur, authoritative)
}

func (r *Recorder) RecordSRV(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseSRV(ident.DomainName, entry)
		if err != nil {
			continue
		}
		// Key excludes weight (it is the mutable field -> "updated", not a new key).
		key := fmt.Sprintf("%s|%d|%d", v.Target, v.Port, v.Priority)
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{
				"target": v.Target, "port": v.Port, "weight": v.Weight, "priority": v.Priority,
			}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateSRV(ctx, store.RecordsCreateSRVParams{
					DomainID: domainID, Target: v.Target,
					Port: int32(v.Port), Weight: int32(v.Weight), Priority: int32(v.Priority),
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetSRVByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load SRV records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%s|%d|%d", row.Target, row.Port, row.Priority)
		cur[key] = currentEntity{
			payload: PayloadJSON(map[string]any{
				"target": row.Target, "port": int(row.Port),
				"weight": int(row.Weight), "priority": int(row.Priority),
			}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteSRV(ctx, store.RecordsDeleteSRVParams{
					DomainID: domainID, Target: row.Target, Port: row.Port, Priority: row.Priority,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntitySRVRecord, obs, cur, authoritative)
}

func (r *Recorder) RecordSOA(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	const soaKey = "soa" // singleton per domain
	obs := make(map[string]observedEntity, 1)
	for _, entry := range entries {
		v, err := dnsrecords.ParseSOARecord(ident.DomainName, entry)
		if err != nil {
			continue
		}
		obs[soaKey] = observedEntity{
			payload: PayloadJSON(map[string]any{
				"nameserver": v.NameServer, "email": v.AdminEmail, "serial": int64(v.Serial),
				"refresh": v.Refresh, "retry": v.Retry, "expire": v.Expire, "minimum_ttl": v.MinimumTTL,
			}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateSOA(ctx, store.RecordsCreateSOAParams{
					DomainID: domainID, Nameserver: v.NameServer, Email: v.AdminEmail,
					Serial: int64(v.Serial), Refresh: int32(v.Refresh), Retry: int32(v.Retry),
					Expire: int32(v.Expire), MinimumTtl: int32(v.MinimumTTL),
				})
				return e
			},
		}
		break
	}
	rows, err := r.q.RecordsGetSOAByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load SOA records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		cur[soaKey] = currentEntity{
			payload: PayloadJSON(map[string]any{
				"nameserver": row.Nameserver, "email": row.Email, "serial": row.Serial,
				"refresh": int(row.Refresh), "retry": int(row.Retry),
				"expire": int(row.Expire), "minimum_ttl": int(row.MinimumTtl),
			}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteSOA(ctx, domainID)
			},
		}
	}
	return r.sync(ctx, ident, EntitySOARecord, obs, cur, authoritative)
}

func (r *Recorder) RecordCAA(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseCAA(ident.DomainName, entry)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%s|%s", v.Tag, v.Value)
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{"flags": v.Flag, "tag": v.Tag, "value": v.Value}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateCAA(ctx, store.RecordsCreateCAAParams{
					DomainID: domainID, Flags: int32(v.Flag), Tag: v.Tag, Value: v.Value,
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetCAAByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load CAA records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%s|%s", row.Tag, row.Value)
		cur[key] = currentEntity{
			payload: PayloadJSON(map[string]any{"flags": int(row.Flags), "tag": row.Tag, "value": row.Value}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteCAA(ctx, store.RecordsDeleteCAAParams{
					DomainID: domainID, Tag: row.Tag, Value: row.Value,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntityCAARecord, obs, cur, authoritative)
}

func (r *Recorder) RecordDNSKEY(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseDNSKEY(ident.DomainName, entry)
		if err != nil {
			continue
		}
		key := v.PublicKey
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{
				"public_key": v.PublicKey, "flags": v.Flags, "protocol": v.Protocol, "algorithm": v.Algorithm,
			}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateDNSKEY(ctx, store.RecordsCreateDNSKEYParams{
					DomainID: domainID, PublicKey: v.PublicKey,
					Flags: int32(v.Flags), Protocol: int32(v.Protocol), Algorithm: int32(v.Algorithm),
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetDNSKEYByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load DNSKEY records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		cur[row.PublicKey] = currentEntity{
			payload: PayloadJSON(map[string]any{
				"public_key": row.PublicKey, "flags": int(row.Flags),
				"protocol": int(row.Protocol), "algorithm": int(row.Algorithm),
			}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteDNSKEY(ctx, store.RecordsDeleteDNSKEYParams{
					DomainID: domainID, PublicKey: row.PublicKey,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntityDNSKEYRecord, obs, cur, authoritative)
}

func (r *Recorder) RecordDS(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseDS(ident.DomainName, entry)
		if err != nil {
			continue
		}
		key := v.Digest
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{
				"key_tag": v.KeyTag, "algorithm": v.Algorithm, "digest_type": v.DigestType, "digest": v.Digest,
			}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateDS(ctx, store.RecordsCreateDSParams{
					DomainID: domainID, KeyTag: int32(v.KeyTag), Algorithm: int32(v.Algorithm),
					DigestType: int32(v.DigestType), Digest: v.Digest,
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetDSByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load DS records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		cur[row.Digest] = currentEntity{
			payload: PayloadJSON(map[string]any{
				"key_tag": int(row.KeyTag), "algorithm": int(row.Algorithm),
				"digest_type": int(row.DigestType), "digest": row.Digest,
			}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteDS(ctx, store.RecordsDeleteDSParams{
					DomainID: domainID, Digest: row.Digest,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntityDSRecord, obs, cur, authoritative)
}

func (r *Recorder) RecordRRSIG(
	ctx context.Context,
	ident DomainIdentity,
	entries []string,
	authoritative bool,
) error {
	domainID := pgtype.Int4{Int32: ident.DomainID, Valid: true}
	obs := make(map[string]observedEntity, len(entries))
	for _, entry := range entries {
		v, err := dnsrecords.ParseRRSIG(ident.DomainName, entry)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%d|%s", v.TypeCovered, v.SignerName)
		obs[key] = observedEntity{
			payload: PayloadJSON(map[string]any{
				"type_covered": v.TypeCovered, "algorithm": v.Algorithm, "labels": v.Labels,
				"original_ttl": v.OriginalTTL, "expiration": v.Expiration, "inception": v.Inception,
				"key_tag": v.KeyTag, "signer_name": v.SignerName, "signature": v.Signature,
			}),
			upsert: func(ctx context.Context) error {
				_, e := r.q.RecordsCreateRRSIG(ctx, store.RecordsCreateRRSIGParams{
					DomainID: domainID, TypeCovered: int32(v.TypeCovered), Algorithm: int32(v.Algorithm),
					Labels: int32(v.Labels), OriginalTtl: int32(v.OriginalTTL), Expiration: int32(v.Expiration),
					Inception: int32(v.Inception), KeyTag: int32(v.KeyTag),
					SignerName: v.SignerName, Signature: v.Signature,
				})
				return e
			},
		}
	}
	rows, err := r.q.RecordsGetRRSIGByDomainID(ctx, domainID)
	if err != nil {
		return fmt.Errorf("load RRSIG records: %w", err)
	}
	cur := make(map[string]currentEntity, len(rows))
	for _, row := range rows {
		key := fmt.Sprintf("%d|%s", row.TypeCovered, row.SignerName)
		cur[key] = currentEntity{
			payload: PayloadJSON(map[string]any{
				"type_covered": int(row.TypeCovered), "algorithm": int(row.Algorithm), "labels": int(row.Labels),
				"original_ttl": int(row.OriginalTtl), "expiration": int(row.Expiration), "inception": int(row.Inception),
				"key_tag": int(row.KeyTag), "signer_name": row.SignerName, "signature": row.Signature,
			}),
			delete: func(ctx context.Context) error {
				return r.q.RecordsDeleteRRSIG(ctx, store.RecordsDeleteRRSIGParams{
					DomainID: domainID, TypeCovered: row.TypeCovered, SignerName: row.SignerName,
				})
			},
		}
	}
	return r.sync(ctx, ident, EntityRRSIGRecord, obs, cur, authoritative)
}
