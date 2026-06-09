# Malicious Inbox Rule Detection: Financial and Sensitive Keyword Focus (Cortex XQL)

> Author: **Abdalla Elzedy**, Security Engineer

A Cortex XSIAM / XDR hunting query that surfaces Exchange Online inbox-rule activity
referencing finance or sensitive-data terms. Attacker-created mail rules that hide,
forward, or auto-delete messages about invoices, wire transfers, payroll, or
credentials are a hallmark of Business Email Compromise (BEC) and email-hiding
tradecraft, so rule changes that mention those terms are worth a closer look.

**MITRE ATT&CK:** T1564.008 (Email Hiding Rules), T1114 (Email Collection)

> **Note:** This query contains no organization-specific identifiers, so no
> sanitization or placeholders are required. It is safe to run as-is and to publish.

## What it does

1. Scopes to the last 30 days of Exchange Online inbox-rule operations
   (`New-`, `Set-`, `Enable-`, `Disable-`, `Remove-`, `Update`, and `Get-InboxRule`).
2. Extracts the relevant rule parameters (rule name, sender, identity, subject terms)
   from the audit `Parameters` array.
3. Normalizes those fields into a single lowercase string and matches it against a
   curated list of finance / sensitive-data keywords.
4. Geolocates the source `ClientIP` and resolves its ASN/owner.
5. Returns a time-sorted result set with the matched terms highlighted for triage.

## Query

```xql
// ============================================================================
// Malicious Inbox Rule Detection (Financial / Sensitive Keyword Focus)
// ----------------------------------------------------------------------------
// Purpose : Surface Exchange Online inbox-rule activity referencing finance or
//           sensitive-data keywords, a common indicator of BEC and email-hiding
//           tradecraft.
// Author  : Abdalla Elzedy, Security Engineer
// Source  : msft_o365_exchange_online_raw
// ATT&CK  : T1564.008 (Email Hiding Rules), T1114 (Email Collection)
// Window  : Last 30 days
// ============================================================================

dataset = msft_o365_exchange_online_raw

// --- Scope: last 30 days of inbox-rule operations ---------------------------
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 2592000), "SECONDS")
| filter Operation in (
    "New-InboxRule", "Set-InboxRule", "Enable-InboxRule",
    "UpdateInboxRules", "Remove-InboxRule", "Disable-InboxRule", "Get-InboxRule"
  )

// --- Extract rule parameters from the audit Parameters array ----------------
| alter parameters_array = json_extract_array(to_json_string(Parameters), "$")
| alter
    AlwaysDeleteOutlookRulesBlob = json_extract_scalar(to_json_string(arrayindex(parameters_array, 0)), "$.Value"),
    Force                        = json_extract_scalar(to_json_string(arrayindex(parameters_array, 1)), "$.Value"),
    Identity                     = json_extract_scalar(to_json_string(arrayindex(parameters_array, 2)), "$.Value"),
    From                         = json_extract_scalar(to_json_string(arrayindex(parameters_array, 3)), "$.Value"),
    RuleName                     = json_extract_scalar(to_json_string(arrayindex(parameters_array, 4)), "$.Value"),
    SubjectContainsWords         = json_extract_scalar(to_json_string(arrayindex(parameters_array, 5)), "$.Value"),
    StopProcessingRules          = json_extract_scalar(to_json_string(arrayindex(parameters_array, 6)), "$.Value")

// --- Normalize searchable text ----------------------------------------------
| alter combined_fields = lowercase(concat(From, " ", RuleName, " ", SubjectContainsWords, " ", Identity))

// --- Keyword match (finance / sensitive-data terms) -------------------------
| filter combined_fields ~= "accounting|agreement|bank|bic|capital call|cash|confidential|contribution|credentials|credit|deposit|dividend|docusign|finance|fund|iban|invoice|password|payment|payroll|purchase|sensitive|shares|ssn|statement|swift|tax|transfer|w2|wire|wiring info|withdrawal"

// --- Geolocate source IP ----------------------------------------------------
| alter ClientIP = arrayindex(split(ClientIP, ":"), 0)
| iploc ClientIP suffix = _geo
| alter location = concat(loc_city_geo, ", ", loc_region_geo)

// --- Present results --------------------------------------------------------
| sort desc _time
| fields _time, Operation, UserId, ClientIP, From, RuleName, Identity, location, loc_asn_org_geo as ASN
| view highlight fields = RuleName, From, Identity values =
    "accounting", "agreement", "bank", "bic", "capital call", "cash",
    "confidential", "contribution", "credentials", "credit", "deposit",
    "dividend", "docusign", "finance", "fund", "iban", "invoice", "password",
    "payment", "payroll", "purchase", "sensitive", "shares", "ssn",
    "statement", "swift", "tax", "transfer", "w2", "wire", "wiring info",
    "withdrawal"
```

## What changed from the original

- **Collapsed the keyword filter.** The original used 31 chained
  `string_count(combined_fields, "...") > 0 or ...` lines. These are replaced by a
  single regex `~=` match with the same terms, which is easier to read and maintain
  and preserves the original substring-matching behavior.
- **Removed dead code.** The original computed `latitude` and `longitude` but never
  output them. They are dropped here. See the note below to add them back for mapping.
- **Synced the keyword lists.** `iban` was present in the filter but missing from the
  `view highlight` list in the original. Both lists now match.
- **Formatting and documentation.** Added a documented header, grouped the pipeline
  into labeled stages, and aligned the parameter assignments for readability.

## Hardening notes

These are worth understanding before relying on the results:

- **Positional parameter extraction is fragile.** Pulling parameters by array index
  (`arrayindex(parameters_array, 4)` for `RuleName`, etc.) assumes the audit
  `Parameters` array always arrives in the same order. O365 does not strictly
  guarantee this across cmdlets or over time. Validate the ordering against recent
  events in your own tenant, and consider extracting by parameter `Name` if your data
  shows the order drifting.
- **IPv6 addresses.** `arrayindex(split(ClientIP, ":"), 0)` is meant to strip an
  `IPv4:port` suffix, but it also truncates IPv6 addresses (which contain colons).
  If your tenant logs IPv6 client IPs, handle them separately before this step.
- **Substring matching causes false positives.** Short terms match inside larger
  words (for example `bic` in "public", `tax` in "syntax", `cash` in "cashier",
  `wire` in "wireless"). If noise is high, switch the regex to word-boundary matches
  (for example `\baccounting\b|\bbank\b|...`) to tighten precision.
- **Keyword list lives in two places.** The match filter and the `view highlight`
  list must be kept in sync when you add or remove terms.

## Optional enhancements

- **Re-add coordinates for mapping.** If you want to plot results, restore:
  `| alter latitude = arrayindex(split(loc_latlon_geo, ","), 0), longitude = arrayindex(split(loc_latlon_geo, ","), 1)`
  and include `latitude, longitude` in the `fields` list.
- **Tighten on high-risk operations.** To focus on rule creation and modification
  only, narrow the `Operation in (...)` list to `New-InboxRule`, `Set-InboxRule`,
  and `UpdateInboxRules`.

## Credit

Authored by **Abdalla Elzedy**, Security Engineer.
