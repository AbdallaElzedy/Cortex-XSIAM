# NGFW Threat Intelligence & Hunting Query

Advanced Cortex XSIAM XQL query for threat analysis and hunting using Palo Alto Networks NGFW threat logs.

## Query

```xql
// ===================================================================
//  NGFW THREAT INTELLIGENCE & HUNTING QUERY
// ===================================================================
// Purpose: Threat analysis focusing on high-value threats
// Excludes: Low-value noise (TCP SYN with data, TCP Flood, TCP Fast Open)
// Author: Abdalla Elzedy - Security Engineer
// ===================================================================
dataset = panw_ngfw_threat_raw
| filter log_type = "threat"
// ===== NOISE REDUCTION FILTER =====
// Exclude high-volume, low-value threats based on your environment
| filter threat_name not in (
    "TCP SYN with data",
    "TCP Flood", 
    "TCP Fast Open",
    "Modified From stun To dtls",
    "Modified From ssl web-browsing To ms-office365-copilot"
)
// ===== FOCUS ON ACTIONABLE THREATS =====
| filter threat_category in (
    "dns", "dns-c2", "spyware", "code-execution", "brute-force", 
    "scan", "info-leak", "protocol-anomaly"
) or severity in ("Critical", "High")
// ===== TIME FILTER =====
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
// ===== THREAT ENRICHMENT =====
| alter threat_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
       threat_hour = extract_time(_time, "HOUR"),
       threat_date = format_timestamp("%Y-%m-%d", _time),
       time_category = if(
           extract_time(_time, "HOUR") >= 9 and extract_time(_time, "HOUR") <= 17, "Business Hours",
           extract_time(_time, "HOUR") >= 18 and extract_time(_time, "HOUR") <= 23, "After Hours",
           "Night/Weekend"
       ),
// ===== RISK CLASSIFICATION =====
       threat_risk_level = if(
           threat_category in ("dns-c2", "code-execution") or severity = "Critical", "CRITICAL",
           threat_category in ("spyware", "brute-force") and severity = "High", "HIGH",
           threat_category = "dns" and action = "drop", "HIGH",
           threat_category in ("scan", "info-leak") and severity in ("High", "Medium"), "MEDIUM",
           "LOW"
       ),
// ===== NETWORK CONTEXT =====
       connection_context = concat(
           "Proto:", protocol, " ",
           if(is_nat = true, concat("NAT(", nat_source, "->", source_ip, ")"), concat("Direct(", source_ip, ")")),
           " Port:", to_string(dest_port)
       ),
// ===== GEOGRAPHIC INTELLIGENCE =====
       geo_context = concat(
           coalesce(source_location, "Unknown"), " -> ", 
           coalesce(dest_location, "Unknown")
       ),
// ===== ACTION EFFECTIVENESS =====
       security_action_taken = if(
           action = "drop", "BLOCKED",
           action = "alert", "DETECTED_ONLY",
           action = "allow", "ALLOWED_THREAT",
           action
       ),
// ===== APPLICATION RISK =====
       app_risk_context = concat(
           coalesce(app, "Unknown"), 
           if(app_category != null, concat(" [", app_category, "]"), ""),
           if(risk_of_app != null, concat(" Risk:", risk_of_app), "")
       )
// ===== COMPREHENSIVE THREAT PROFILING =====
| comp 
    // Threat Summary
    count() as total_threats,
    count_distinct(threat_date) as days_active,
    count_distinct(source_ip) as unique_sources,
    count_distinct(dest_ip) as unique_targets,
    earliest(_time) as first_seen,
    latest(_time) as last_seen,
    // Risk Metrics
    sum(if(action = "allow", 1, 0)) as threats_allowed,
    sum(if(action = "drop", 1, 0)) as threats_blocked,
    sum(if(action = "alert", 1, 0)) as threats_detected,
    sum(if(severity = "Critical", 1, 0)) as critical_threats,
    sum(if(severity = "High", 1, 0)) as high_threats,
    // Behavioral Patterns
    count_distinct(threat_hour) as hours_active,
    count_distinct(dest_port) as unique_ports,
    count_distinct(session_id) as unique_sessions,
    // DNS Intelligence (for DNS threats)
    count_distinct(if(threat_category = "dns", threat_name, null)) as unique_dns_threats,
    // Network Intelligence
    values(connection_context) as connection_patterns,
    values(geo_context) as geographic_patterns,
    values(app_risk_context) as application_patterns,
    values(rule_matched) as firewall_rules,
    // Temporal Intelligence
    values(time_category) as attack_time_patterns,
    values(threat_hour) as attack_hours,
    // Technical Details
    values(protocol) as protocols_used,
    values(security_action_taken) as security_responses,
    values(threat_risk_level) as risk_levels,
    // Raw Evidence
    list(threat_timestamp) as all_threat_times,
    list(connection_context) as all_connections,
    list(dest_port) as all_dest_ports
    // Group by threat intelligence
    by threat_name, 
       threat_category, 
       severity,
       source_ip,
       source_location
// ===== ADVANCED ANALYTICS =====
| alter 
    // Calculate threat persistence and patterns
    threat_duration_days = timestamp_diff(last_seen, first_seen, "DAY"),
    avg_threats_per_day = if(
        timestamp_diff(last_seen, first_seen, "DAY") > 0,
        divide(total_threats, timestamp_diff(last_seen, first_seen, "DAY")),
        total_threats
    ),
    // Risk scoring algorithm
    threat_score = add(
        add(
            add(
                multiply(threats_allowed, 20),              // 20 points per allowed threat
                multiply(critical_threats, 15)              // 15 points per critical
            ),
            add(
                multiply(high_threats, 10),                 // 10 points per high severity
                multiply(threats_detected, 5)               // 5 points per detection
            )
        ),
        add(
            if(days_active > 7, 10, 0),                    // 10 points for persistence
            if(hours_active > 12, 5, 0)                    // 5 points for 24/7 activity
        )
    )
| alter
    // Source classification
    source_profile = if(
        threats_allowed > 0, "CRITICAL_COMPROMISE",
        threat_score > 50, "HIGH_RISK_SOURCE",
        days_active > 14, "PERSISTENT_THREAT_SOURCE",
        total_threats > 50, "HIGH_VOLUME_SOURCE",
        unique_targets > 10, "SCANNING_SOURCE",
        "STANDARD_SOURCE"
    ),
    // Calculate block ratio
    block_ratio = if(
        total_threats > 0,
        divide(threats_blocked, total_threats),
        0
    )
| alter
    // Threat pattern analysis
    attack_pattern = if(
        hours_active > 20, "24x7_PERSISTENT",
        attack_time_patterns contains "Night/Weekend" and attack_time_patterns contains "Business Hours", "MIXED_TIMING",
        attack_time_patterns contains "Business Hours", "BUSINESS_HOURS",
        "OFF_HOURS"
    ),
    // Threat recency assessment
    threat_recency = if(
        timestamp_diff(current_time(), last_seen, "HOUR") < 1, "ACTIVE_NOW",
        timestamp_diff(current_time(), last_seen, "HOUR") < 24, "RECENT_24H",
        timestamp_diff(current_time(), last_seen, "DAY") < 7, "THIS_WEEK",
        "HISTORICAL"
    )
| alter
    // DNS threat focus (for DNS categories)
    dns_threat_summary = if(
        threat_category in ("dns", "dns-c2"),
        concat("DNS Threats: ", to_string(unique_dns_threats), " unique signatures"),
        "N/A"
    )
// ===== FINAL ENRICHMENT =====
| alter 
    investigation_priority = concat(
        source_profile, " | ",
        "Score:", to_string(threat_score), " | ",
        "Pattern:", attack_pattern, " | ",
        "Status:", threat_recency
    ),
    first_seen_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", first_seen),
    last_seen_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", last_seen),
    effectiveness_ratio = multiply(block_ratio, 100)
// ===== PRIORITIZED OUTPUT =====
| fields 
    // Primary Threat Intelligence
    threat_name, threat_category, severity, source_ip, source_location,
    // Investigation Priority
    investigation_priority, threat_score, source_profile,
    // Threat Overview
    total_threats, days_active, threat_duration_days, avg_threats_per_day,
    first_seen_formatted, last_seen_formatted, threat_recency,
    // Security Effectiveness
    threats_allowed, threats_blocked, threats_detected, effectiveness_ratio,
    critical_threats, high_threats,
    // Attack Intelligence
    attack_pattern, attack_time_patterns, hours_active,
    unique_targets, unique_ports, unique_sessions,
    // DNS Threat Intelligence (when applicable)
    dns_threat_summary, unique_dns_threats,
    // Technical Evidence
    application_patterns, connection_patterns, protocols_used,
    security_responses, firewall_rules, geographic_patterns,
    // Forensic Details
    all_threat_times, all_connections, all_dest_ports
// ===== SORT BY PRIORITY =====
| sort desc threat_score, desc threats_allowed, desc critical_threats, desc total_threats
// ===== LIMIT FOR PERFORMANCE =====
| limit 100
```

## What It Does

- **Intelligent Noise Filtering**: Excludes high-volume, low-value threats like TCP SYN floods
- **Actionable Threat Focus**: Concentrates on DNS, C2, spyware, code execution, and brute force attacks
- **Risk Scoring**: Multi-factor algorithm prioritizing allowed threats and critical events
- **Behavioral Analysis**: Identifies 24/7 persistent threats and attack patterns
- **Source Classification**: Categorizes sources as compromised, high-risk, or scanning
- **Geographic Intelligence**: Maps attack sources and destinations
- **Security Effectiveness**: Tracks blocking ratios and policy effectiveness

## Key Output Fields

| Field | Description |
|-------|-------------|
| `threat_name` | Specific threat signature detected |
| `source_profile` | Source classification (CRITICAL_COMPROMISE, HIGH_RISK_SOURCE, etc.) |
| `threat_score` | Calculated risk score based on multiple factors |
| `threats_allowed` | Number of threats that were allowed through |
| `threats_blocked` | Number of threats successfully blocked |
| `attack_pattern` | Temporal attack analysis (24x7_PERSISTENT, BUSINESS_HOURS, etc.) |
| `effectiveness_ratio` | Percentage of threats successfully blocked |
| `dns_threat_summary` | DNS-specific threat intelligence |

## Risk Scoring Algorithm

- **20 points** per allowed threat (highest priority)
- **15 points** per critical severity threat
- **10 points** per high severity threat
- **5 points** per detected/alerted threat
- **10 points** for persistent activity (>7 days)
- **5 points** for 24/7 activity patterns

## Source Classifications

- **CRITICAL_COMPROMISE**: Sources with allowed threats (immediate investigation)
- **HIGH_RISK_SOURCE**: High threat scores (>50 points)
- **PERSISTENT_THREAT_SOURCE**: Active for >14 days
- **HIGH_VOLUME_SOURCE**: >50 threats generated
- **SCANNING_SOURCE**: Targeting >10 different destinations
- **STANDARD_SOURCE**: Normal activity levels


## Customization

- **Threat Categories**: Add/remove categories in the focus filter
