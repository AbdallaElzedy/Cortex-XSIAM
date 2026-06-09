# Account Takeover (ATO) Chain Detection (Cortex XQL)

> Author: **Abdalla Elzedy**, Security Engineer

A correlation query for **Cortex XSIAM / XDR** that stitches together identity, VPN,
email, and web activity per user to surface account-takeover patterns. For example,
an attacker who enrolls a new MFA device, creates a mail-forwarding/hiding inbox rule,
deletes evidence, and touches sensitive internal apps within a short window.

> **Note:** All organization-specific values (email domain, trusted location, and
> internal/SaaS app names) have been replaced with `<PLACEHOLDERS>`. See
> [Customization](#customization) before running this in your own tenant.

## What it does

It unions six event streams into a single normalized timeline per `userid`:

| `event_type`     | Source dataset                       | Signal |
|------------------|--------------------------------------|--------|
| `LOGIN`          | Azure / Entra sign-in logs           | Successful interactive + non-interactive sign-ins |
| `DUO_ENROLLMENT` | Duo logs                             | New phone-number MFA device enrolled from outside the trusted location |
| `VPN_CONNECT`    | PAN-OS GlobalProtect                 | VPN session established |
| `EMAIL_DELETE`   | O365 Exchange Online                 | Soft/Hard delete or move-to-deleted of `*csv*` / `*device*` items |
| `INBOX_RULE`     | O365 Exchange Online                 | New/Set inbox rule whose name matches suspicious keywords |
| `SENSITIVE_APP`  | PAN-OS URL filtering                 | Access to sensitive internal app URLs |

It then aggregates by user, computes the activity time span, and assigns a
`severity` based on which behaviors co-occur and how fast. Inbox-rule + delete
combinations are treated as **CRITICAL** (classic ATO).

## Query

```xql
config case_sensitive = false

// ============================================================================
// COLLECT ALL USER ACTIVITY WITH TIMESTAMPS
// ============================================================================
dataset = msft_azure_raw
| filter category in ("SignInLogs", "NonInteractiveUserSignInLogs")
| alter userid = json_extract_scalar(properties, "$.userPrincipalName")
| alter ip = json_extract_scalar(properties, "$.ipAddress")
| alter resultType = to_string(resultType)
| filter resultType = "0"
| alter event_time = _time
| alter event_type = "LOGIN"
| alter detail = json_extract_scalar(properties, "$.appDisplayName")

| union (
    dataset = duo_duo_raw
    | filter event_type = "enrollment"
    | alter userid = concat(user -> name , "@<YOUR_EMAIL_DOMAIN>")
    | alter access_device_ip = access_device -> ip
    | alter device = auth_device -> name
    | alter event_type = "DUO_ENROLLMENT"
    | alter device_type = if (len(device) > 11 and len(device) < 20, "Phone_Number",
        if (len(device) = 20, "Device_ID", device))
    | filter device_type = "Phone_Number"
    | filter device != "Generic Smartphone"
    | alter access_device_city = json_extract_scalar(to_json_string(access_device), "$.location.city"),
        access_device_state = json_extract_scalar(to_json_string(access_device), "$.location.state"),
        access_device_country = json_extract_scalar(to_json_string(access_device), "$.location.country")
    | alter access_device_location = concat(access_device_city, ", ", access_device_state, ", ", access_device_country)
    | filter access_device_location != "<YOUR_TRUSTED_LOCATION>"   // e.g. "City, State, Country"
    | fields _time, userid, event_type, device_type, device, access_device_location, access_device_ip, factor, result
)

| union (
    dataset = panw_ngfw_globalprotect_raw
    | alter userid = source_user
    | alter ip = public_ip
    | alter event_time = _time
    | alter event_type = "VPN_CONNECT"
    | alter detail = endpoint_device_name
)

| union (
    dataset = msft_o365_exchange_online_raw
    | filter Operation in ("SoftDelete", "HardDelete", "MoveToDeletedItems")
    | alter userid = UserId
    | alter ip = arrayindex(split(ClientIPAddress, ":"), 0)
    | alter event_time = _time
    | alter event_type = "EMAIL_DELETE"
    | alter affected_array = json_extract_array(AffectedItems, "$")
    | arrayexpand affected_array
    | alter Subject = json_extract_scalar(affected_array, "$.Subject")
    | filter Subject ~= ".*csv.*|.*device.*"
    | alter detail = Operation
)

| union (
    dataset = msft_o365_exchange_online_raw
    | filter Operation in ("New-InboxRule", "Set-InboxRule")
    | alter userid = UserId
    | alter ip = arrayindex(split(ClientIPAddress, ":"), 0)
    | alter parameters_array = json_extract_array(to_json_string(Parameters), "$")
    | alter RuleName = json_extract_scalar(to_json_string(arrayindex(parameters_array, 4)), "$.Value")
    | filter RuleName ~= ".*download.*|.*csv.*|.*report.*|.*ready.*|.*export.*|.*prepared.*|.*<SAAS_APP_1>.*|.*<SAAS_APP_2>.*|.*<SAAS_APP_3>.*|.*login.*|.*duo.*|.*duo mobile.*"
    | alter event_time = _time
    | alter event_type = "INBOX_RULE"
    | alter detail = Operation
)

| union (
    dataset = panw_ngfw_url_raw
    | filter log_type = "threat" and sub_type = "url"
    | filter uri ~= ".*<SENSITIVE_APP_1>.*|.*<SENSITIVE_APP_2>.*|.*<SENSITIVE_APP_3>.*"
    | alter userid = users
    | alter ip = source_ip
    | alter event_time = _time
    | alter event_type = "SENSITIVE_APP"
    | alter detail = url_domain
)

| filter userid != null and userid != ""

// ============================================================================
// AGGREGATE BY USER - LOOK AT ENTIRE ACTIVITY WINDOW
// ============================================================================
| comp
    earliest(event_time) as first_event,
    latest(event_time) as last_event,
    count_distinct(event_type) as event_types_count,
    values(event_type) as event_types,
    count() as total_events,
    count_distinct(ip) as unique_ips,
    values(ip) as all_ips,
    values(detail) as activity_details
    by userid

// Calculate actual time span
| alter time_span_minutes = timestamp_diff(last_event, first_event, "MINUTE")

// ============================================================================
// DETECT SUSPICIOUS PATTERNS - INCLUDING INBOX RULES
// ============================================================================
| alter event_types_str = arraystring(event_types, ",")

| alter has_login = if(event_types_str contains "LOGIN", 1, 0)
| alter has_duo_enrollment = if(event_types_str contains "DUO_ENROLLMENT", 1, 0)
| alter has_vpn = if(event_types_str contains "VPN_CONNECT", 1, 0)
| alter has_email_delete = if(event_types_str contains "EMAIL_DELETE", 1, 0)
| alter has_inbox_rule = if(event_types_str contains "INBOX_RULE", 1, 0)
| alter has_sensitive_app = if(event_types_str contains "SENSITIVE_APP", 1, 0)

// Severity based on combination and speed - INBOX RULES ARE CRITICAL
| alter severity = ""
| alter severity = if(has_inbox_rule = 1 and has_email_delete = 1, "CRITICAL - Rule+Delete (Classic ATO)", severity)
| alter severity = if(has_login = 1 and has_vpn = 1 and has_inbox_rule = 1 and time_span_minutes <= 30, "CRITICAL - Full ATO Chain", severity)
| alter severity = if(has_inbox_rule = 1 and time_span_minutes <= 30 and severity = "", "CRITICAL - Rapid Inbox Rule", severity)
| alter severity = if(has_login = 1 and has_vpn = 1 and has_email_delete = 1 and time_span_minutes <= 30 and severity = "", "CRITICAL - Login+VPN+Delete", severity)
| alter severity = if(has_login = 1 and has_vpn = 1 and time_span_minutes <= 15 and severity = "", "HIGH - Rapid Login+VPN", severity)
| alter severity = if(has_vpn = 1 and has_email_delete = 1 and severity = "", "HIGH - VPN+Delete", severity)
| alter severity = if(has_email_delete = 1 and has_sensitive_app = 1 and severity = "", "HIGH - Delete+Apps", severity)
| alter severity = if(has_inbox_rule = 1 and severity = "", "HIGH - Inbox Rule Created", severity)
| alter severity = if(event_types_count >= 3 and time_span_minutes <= 60 and severity = "", "MEDIUM - Multiple Activities", severity)
| alter severity = if(has_login = 1 and has_vpn = 1 and severity = "", "MEDIUM - Login+VPN", severity)

// Filter to only suspicious activity
//| filter severity != ""

| alter attack_chain = arraystring(event_types, " -> ")
| alter first_event_fmt = format_timestamp("%Y-%m-%d %H:%M:%S", first_event, "America/New_York")
| alter last_event_fmt = format_timestamp("%Y-%m-%d %H:%M:%S", last_event, "America/New_York")

| fields
    severity,
    userid,
    first_event_fmt,
    last_event_fmt,
    attack_chain,
    event_types_count,
    total_events,
    unique_ips,
    all_ips,
    activity_details,
    time_span_minutes

//| filter severity contains "CRITICAL"
//| filter event_types_count > 3
//| filter attack_chain contains "inbox"
| sort desc event_types_count
```

## Customization

Replace these placeholders with values for your environment before running:

| Placeholder | Replace with | Used for |
|-------------|--------------|----------|
| `<YOUR_EMAIL_DOMAIN>` | Your org email domain, e.g. `example.edu` | Building `userid` from the Duo username |
| `<YOUR_TRUSTED_LOCATION>` | Your trusted office location string, e.g. `City, State, Country` | Filtering out enrollments from a known-good location |
| `<SAAS_APP_1..3>` | Inbox-rule name keywords for the SaaS apps you care about | Suspicious inbox-rule name matching |
| `<SENSITIVE_APP_1..3>` | URL/hostname fragments for your sensitive internal apps | Detecting access to sensitive apps |

Also confirm the **dataset names** (`msft_azure_raw`, `duo_duo_raw`,
`panw_ngfw_globalprotect_raw`, `msft_o365_exchange_online_raw`, `panw_ngfw_url_raw`)
match your tenant's ingested datasets, and adjust the timezone in
`format_timestamp(...)` if you're not on `America/New_York`.

## Tuning tips

- The commented `| filter` lines at the end let you scope output to only
  `CRITICAL` findings, high event-type counts, or chains involving inbox rules.
  Uncomment as needed.
- The Duo `device_type` heuristic infers "phone number" from string length
  (`> 11 and < 20`). Validate this against your own Duo log formatting.
- Time-window thresholds (`<= 30`, `<= 15`, `<= 60` minutes) are starting points.
  Tune them to your environment's noise level.
