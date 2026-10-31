# Inventory contract

The local inventory input is `data/inventory.json`. Its current format is a JSON object with an explicit `schema_version` and an `assets` array:

```json
{
  "schema_version": "1.0",
  "assets": [
    {
      "asset_id": "A-201",
      "asset_type": "application",
      "service": "payments-api",
      "vendor": "Apache",
      "product": "log4j-core",
      "component": "log4j-core",
      "version": "2.14.1",
      "internet_facing": true,
      "criticality": "high",
      "data_classification": "confidential",
      "owner": "team-payments",
      "owner_contact": "payments@example.invalid",
      "aliases": ["log4j"]
    }
  ]
}
```

`asset_id`, `service`, `component`, `version`, `internet_facing`, `criticality`, and `owner` are required. `asset_id` must be unique without regard to case. `criticality` is `critical`, `high`, `medium`, or `low`. `asset_type` is `application`, `service`, `vendor_product`, or `saas` and defaults to `application`. `vendor`, `product`, `owner_contact`, `data_classification`, and aliases are optional. `owner_contact` accepts an email or team contact reference up to 254 characters. Data classification is one of `public`, `internal`, `confidential`, or `restricted`.

`product` is the canonical product used for advisory correlation; `component` identifies the installed component/package and is retained in findings. Per-asset aliases are combined with `data/aliases.json`. A conflicting alias-to-product mapping fails inventory validation rather than silently selecting one product. Vendor and product metadata, ownership/contact, classification, version, and exposure are validated before the run; a validated run snapshot stores vendor, owner contact and classification in dedicated columns, and product/type/aliases in its JSON context. Owner contact is never included in LLM prompts. API responses expose owner contact only to roles with the `review` capability (analyst, operator, and admin); read-only viewer, audit-reader, and LLM-audit-reader responses omit it, including the compatibility preview.

The loader temporarily accepts the previous top-level JSON array and interprets it as schema version `1.0`. New and updated inventories should use the versioned object format. Unsupported versions, empty inventories, blank required values, duplicate asset IDs, empty/duplicate aliases, and ambiguous alias mappings are rejected.

The checked-in data is synthetic demo inventory, not a production inventory. The current sample has eight assets; expansion to the requirement's representative fleet size and validation against the approved organizational import remains open in tracker item `INV-01`/gap `G-03`.
