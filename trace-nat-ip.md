# NAT Behavior Analysis Query

This Cortex XSIAM XQL query provides essential insights into how a source IP uses NAT infrastructure, including data transfer patterns, destination analysis, and activity timeframes.

## Query

```xql
// ===================================================================
//  NAT BEHAVIOR SUMMARY QUERY
// ===================================================================
// Purpose: Get essential NAT insights for a source IP
// Author: Abdalla Elzedy - Security Engineer
// ===================================================================
dataset = panw_ngfw_traffic_raw
| filter log_type = "traffic"
| filter source_ip = "<ip>"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
// ===== ESSENTIAL ANALYSIS =====
| alter nat_ip = if(
           is_nat = true and nat_source != "00000000000000000000ffff00000000", 
           nat_source,
           "Direct"
       )
// ===== SUMMARIZE BY NAT IP =====
| comp 
    // Core Statistics
    count() as total_sessions,
    count_distinct(dest_ip) as unique_destinations,
    count_distinct(dest_location) as countries_accessed,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    // Data Transfer
    sum(bytes_total) as total_bytes,
    // Top Destinations
    values(dest_ip) as sample_destinations,
    values(dest_location) as countries_list,
    // Activity Patterns
    count_distinct(extract_time(_time, "HOUR")) as active_hours,
    count_distinct(dest_port) as unique_ports
    by nat_ip
// ===== FINAL FORMATTING =====
| alter 
    usage_period = concat(
        format_timestamp("%Y-%m-%d %H:%M", first_seen), 
        " to ", 
        format_timestamp("%Y-%m-%d %H:%M", last_seen)
    ),
    data_transfer_gb = round(divide(total_bytes, 1073741824))
| alter
    activity_summary = concat(
        to_string(total_sessions), " sessions | ",
        to_string(unique_destinations), " destinations | ",
        to_string(countries_accessed), " countries | ",
        to_string(data_transfer_gb), " GB"
    )
// ===== OUTPUT ESSENTIALS =====
| fields 
    nat_ip,
    usage_period,
    activity_summary,
    data_transfer_gb,
    active_hours,
    unique_ports,
    countries_list
// ===== TOP 3 MOST USED NAT IPs =====
| sort desc data_transfer_gb
| limit 3
```

## What It Does

- **Analyzes NAT Usage**: Shows which NAT IPs are used by a source IP
- **Usage Timeframes**: When NAT IPs were active (from/to timestamps)
- **Activity Summary**: Sessions, destinations, countries, and data transfer in one line
- **Geographic Analysis**: Which countries were accessed through each NAT IP
- **Load Distribution**: How traffic is distributed across multiple NAT IPs

## Output Fields

| Field | Description |
|-------|-------------|
| `nat_ip` | NAT IP address used (or "Direct" for non-NAT traffic) |
| `usage_period` | Time range when this NAT IP was active |
| `activity_summary` | One-line summary: sessions, destinations, countries, data |
| `data_transfer_gb` | Total data transferred in GB |
| `active_hours` | Number of different hours during the day with activity |
| `unique_ports` | Number of different destination ports accessed |
| `countries_list` | List of countries accessed through this NAT IP |

## Sample Output

```
nat_ip           | usage_period                        | activity_summary
<nat_ip>   | 2025-06-03 15:58 to 2025-06-04 15:57 | 11605 sessions | 794 destinations | 17 countries | 3 GB
<nat_ip>    | 2025-06-03 15:58 to 2025-06-04 15:57 | 9319 sessions | 764 destinations | 16 countries | 1 GB  
Direct           | 2025-06-04 13:48 to 2025-06-04 13:51 | 5 sessions | 3 destinations | 1 countries | 0 GB
```

## Customization

- **Change Target IP**: Modify `source_ip = "10.9.73.253"` to investigate any IP
- **Adjust Time Range**: Change `604800` (7 days) to desired time window in seconds


