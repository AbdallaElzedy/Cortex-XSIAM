# XYZ Domain Contact Investigation

XQL query to investigate who contacted .xyz domains and assess risk levels.


## Query

```xql
// ===================================================================
// COMPREHENSIVE URL CONTACT INVESTIGATION QUERY
// ===================================================================
// Purpose:  investigation of who contacted a specific URL/domain
// Use Case: Incident response, threat hunting
// Author: Abdalla Elzedy
// ===================================================================
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
// ===== PRIMARY URL FILTER =====
// Replace with your target URL/domain
| filter url_domain contains "xyz" 
   or uri contains "xyz"
   or url_domain ~= ".*\\.xyz$"
// ===== ENRICH WITH CONTACT METADATA =====
| alter contact_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
       contact_hour = extract_time(_time, "HOUR"),
       contact_day = extract_time(_time, "DAYOFWEEK"),
       contact_date = format_timestamp("%Y-%m-%d", _time),
       time_category = if(
           extract_time(_time, "HOUR") >= 9 and extract_time(_time, "HOUR") <= 17, "Business Hours",
           extract_time(_time, "HOUR") >= 18 and extract_time(_time, "HOUR") <= 23, "After Hours",
           "Night/Weekend"
       ),
// ===== RISK ASSESSMENT =====
       risk_indicators = if(
           action in ("block", "deny"), "BLOCKED_ACCESS",
           severity in ("Critical", "High"), "HIGH_SEVERITY", 
           url_category_list contains "malware" or url_category_list contains "phishing", "MALICIOUS_CATEGORY",
           is_encrypted = false and dest_port = 80, "UNENCRYPTED_HTTP",
           dest_port not in (80, 443, 8080, 8443), "UNUSUAL_PORT",
           "NORMAL"
       ),
// ===== GEOGRAPHIC CONTEXT =====
       source_geo_info = concat(coalesce(source_location, "Unknown"), " -> ", coalesce(dest_location, "Unknown")),
// ===== NETWORK CONTEXT =====
       connection_type = if(
           is_nat = true, concat("NAT (", nat_source, " -> ", source_ip, ")"),
           concat("Direct (", source_ip, ")")
       ),
// ===== APPLICATION ANALYSIS =====
       app_context = concat(
           coalesce(app, "Unknown App"), 
           if(container_of_app != null, concat(" [Container: ", container_of_app, "]"), ""),
           if(is_saas_app = true, " [SaaS]", "")
       ),
// ===== SESSION ANALYSIS =====
       session_info = concat(
           "Session:", to_string(session_id), 
           if(parent_session_id > 0, concat(" Parent:", to_string(parent_session_id)), ""),
           " Port:", to_string(source_port), "->", to_string(dest_port)
       )
// ===== COMPREHENSIVE USER PROFILING =====
| comp 
    // Contact Summary
    count() as total_contacts,
    count_distinct(contact_date) as days_active,
    earliest(_time) as first_contact,
    latest(_time) as last_contact,
    // Behavioral Patterns  
    count_distinct(source_port) as unique_source_ports,
    count_distinct(session_id) as unique_sessions,
    count_distinct(uri) as unique_uri_paths,
    count_distinct(user_agent) as unique_user_agents,
    // Risk Metrics
    sum(if(action in ("block", "deny"), 1, 0)) as blocked_attempts,
    sum(if(severity in ("Critical", "High"), 1, 0)) as high_severity_events,
    sum(if(is_encrypted = false, 1, 0)) as unencrypted_contacts,
    sum(if(dest_port not in (80, 443), 1, 0)) as unusual_port_contacts,
    // Temporal Analysis
    values(time_category) as access_time_patterns,
    values(contact_hour) as hours_accessed,
    count_distinct(contact_hour) as unique_hours,
    // Technical Details
    values(app_context) as applications_used,
    values(connection_type) as connection_methods,
    values(source_geo_info) as geographic_paths,
    values(rule_matched) as firewall_rules_triggered,
    values(uri) as uri_paths_accessed,
    values(http_method) as http_methods_used,
    values(user_agent) as user_agents,
    // Network Intelligence
    values(protocol) as protocols_used,
    values(risk_indicators) as risk_flags,
    values(url_category_list) as url_categories,
    // Raw Evidence
    list(contact_timestamp) as all_contact_times,
    list(session_info) as session_details,
    list(action) as all_actions
    // Group by source identity
    by source_ip, 
       users,
       source_location,
       source_user
// ===== ADVANCED ANALYTICS =====
| alter 
    // Calculate contact frequency and patterns
    contact_duration_days = timestamp_diff(last_contact, first_contact, "DAY"),
    avg_contacts_per_day = if(
        timestamp_diff(last_contact, first_contact, "DAY") > 0,
        divide(total_contacts, timestamp_diff(last_contact, first_contact, "DAY")),
        total_contacts
    ),
    // User identity enrichment
    user_identity = coalesce(users, source_ip),
    username = coalesce(source_user, "Unknown User"),
    // Risk scoring algorithm
    risk_score = add(
        add(
            add(
                multiply(blocked_attempts, 10),           // 10 points per block
                multiply(high_severity_events, 5)         // 5 points per high severity
            ),
            add(
                multiply(unencrypted_contacts, 2),        // 2 points per unencrypted
                multiply(unusual_port_contacts, 3)        // 3 points per unusual port
            )
        ),
        add(
            if(unique_hours > 12, 5, 0),                 // 5 points if accessing 24/7
            if(days_active > 7, 3, 0)                    // 3 points if persistent access
        )
    )
| alter
    // Behavior classification
    user_behavior_profile = if(
        blocked_attempts > 5, "PERSISTENT_VIOLATOR",
        risk_score > 20, "HIGH_RISK_USER", 
        days_active > 30, "LONG_TERM_USER",
        total_contacts > 100, "HEAVY_USER",
        unique_sessions > 50, "FREQUENT_CONNECTOR",
        "NORMAL_USER"
    ),
    // Temporal pattern analysis
    access_pattern = if(
        unique_hours > 16, "24x7_ACCESS",
        access_time_patterns contains "Night/Weekend" and access_time_patterns contains "Business Hours", "MIXED_HOURS",
        access_time_patterns contains "Business Hours", "BUSINESS_ONLY",
        "OFF_HOURS_ONLY"
    ),
    // Contact recency analysis
    contact_recency = if(
        timestamp_diff(current_time(), last_contact, "HOUR") < 1, "VERY_RECENT",
        timestamp_diff(current_time(), last_contact, "HOUR") < 24, "RECENT", 
        timestamp_diff(current_time(), last_contact, "DAY") < 7, "THIS_WEEK",
        timestamp_diff(current_time(), last_contact, "DAY") < 30, "THIS_MONTH",
        "HISTORICAL"
    )
// ===== FINAL ENRICHMENT =====
| alter 
    investigation_summary = concat(
        user_behavior_profile, " | ",
        "Risk:", to_string(risk_score), " | ",
        "Pattern:", access_pattern, " | ", 
        "Recency:", contact_recency
    ),
    first_contact_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", first_contact),
    last_contact_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", last_contact)
// ===== PRIORITIZED OUTPUT =====
| fields 
    // Primary Identity
    source_ip, user_identity, username, source_location,
    // Investigation Summary
    investigation_summary, risk_score, user_behavior_profile,
    // Contact Overview
    total_contacts, days_active, contact_duration_days, avg_contacts_per_day,
    first_contact_formatted, last_contact_formatted, contact_recency,
    // Security Metrics
    blocked_attempts, high_severity_events, risk_flags,
    // Behavioral Intelligence  
    access_pattern, access_time_patterns, unique_hours,
    unique_sessions, unique_source_ports, unique_uri_paths,
    // Technical Evidence
    applications_used, connection_methods, protocols_used,
    uri_paths_accessed, http_methods_used, user_agents,
    firewall_rules_triggered, url_categories,
    // Detailed Forensics (for deep dive)
    all_contact_times, session_details, all_actions
// ===== SORT BY PRIORITY =====
| sort desc risk_score, desc blocked_attempts, desc total_contacts
// ===== LIMIT FOR PERFORMANCE =====
| limit 100
```

## What It Does

- **Identifies users** who contacted .xyz domains
- **Risk scoring** based on blocked attempts, severity, and behavior patterns  
- **Behavioral analysis** including access patterns and frequency
- **Timeline reconstruction** with first/last contact times
- **Geographic tracking** of source and destination locations
- **Technical forensics** with session details and application usage

## Key Outputs

| Field | Description |
|-------|-------------|
| `source_ip` | Source IP address of the user |
| `risk_score` | Calculated risk score (0-100+) |
| `user_behavior_profile` | Classification: PERSISTENT_VIOLATOR, HIGH_RISK_USER, etc. |
| `total_contacts` | Number of times user contacted .xyz domains |
| `blocked_attempts` | Number of blocked connection attempts |
| `access_pattern` | Time-based access pattern analysis |
| `uri_paths_accessed` | Specific URLs/paths accessed |

## Risk Scoring

- **10 points** per blocked attempt
- **5 points** per high severity event  
- **3 points** for unusual port usage
- **2 points** for unencrypted connections
- **5 points** for 24/7 access patterns
- **3 points** for persistent access (>7 days)



## Customization

- Change filter from `.xyz` to other domains by modifying the filter conditions
