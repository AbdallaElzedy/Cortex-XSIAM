# XQL PaloAlto Firewall panw_ngfw URL Analysis Queries

A collection of XQL queries for analyzing Palo Alto Networks NGFW URL filtering logs to extract security insights and detect threats.

## Query Collection

### 1. URL Category Risk Assessment

Identifies potentially risky URL categories and their frequency:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| alter risk_level = if(
    url_category_list contains "malware" or url_category_list contains "phishing" or url_category_list contains "command-and-control", "Critical",
    url_category_list contains "hacking" or url_category_list contains "proxy-avoidance-and-anonymizers", "High", 
    url_category_list contains "questionable" or url_category_list contains "gambling", "Medium",
    url_category_list contains "social-networking" or url_category_list contains "entertainment", "Low",
    "Informational"
)
| comp count() as access_count, 
       count_distinct(source_ip) as unique_users,
       count_distinct(url_domain) as unique_domains,
       values(url_domain) as sample_domains by url_category_list, risk_level
| sort desc access_count
| limit 50
```

### 2. Suspicious URL Patterns Detection

Identifies potentially malicious URL patterns:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| alter suspicious_indicators = if(
    url_domain ~= ".*\\.tk$|.*\\.ml$|.*\\.ga$|.*\\.cf$", "Suspicious TLD",
    url_domain ~= ".*[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}.*", "IP-like Domain",
    len(url_domain) > 50, "Long Domain Name",
    url_domain ~= ".*[a-zA-Z0-9]{20,}.*", "Random String Pattern",
    uri ~= ".*/[a-zA-Z0-9]{32,}", "Long URI Path",
    ""
)
| filter suspicious_indicators != ""
| comp count() as occurrence_count,
       count_distinct(source_ip) as affected_users,
       values(source_ip) as user_list by url_domain, uri, suspicious_indicators, action
| sort desc occurrence_count
| limit 100
```

### 3. Top URL Domains and Applications Analysis

Provides insight into most accessed domains and applications:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 86400), "SECONDS")
| comp count() as access_count,
       count_distinct(source_ip) as unique_users,
       count_distinct(source_port) as unique_sessions,
       avg(if(dest_port != null, dest_port, 0)) as avg_dest_port,
       values(action) as actions_seen by url_domain, app, app_category
| alter popularity_score = multiply(access_count, unique_users)
| sort desc popularity_score
| limit 30
```

### 4. Blocked and Alerted URL Activity

Focuses on security events and policy violations:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter action in ("block", "alert", "deny")
| alter time_bucket = date_floor(_time, "1h")
| comp count() as blocked_attempts,
       count_distinct(source_ip) as affected_users,
       count_distinct(url_domain) as blocked_domains,
       values(rule_matched) as triggered_rules,
       first(severity) as severity_level by time_bucket, action, url_category_list
| sort desc time_bucket, desc blocked_attempts
| limit 100
```

### 5. User Behavior Analysis

Analyzes individual user URL access patterns:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter source_ip != null
| comp count() as total_requests,
       count_distinct(url_domain) as unique_domains,
       count_distinct(app) as unique_apps,
       count_distinct(url_category_list) as unique_categories,
       sum(if(action = "block", 1, 0)) as blocked_requests,
       values(url_category_list) as categories_accessed by source_ip, source_location
| alter block_ratio = divide(blocked_requests, total_requests)
| alter risk_score = if(
    blocked_requests > 10 and block_ratio > 0.1, "High Risk",
    blocked_requests > 5 or unique_categories > 15, "Medium Risk", 
    "Low Risk"
)
| sort desc blocked_requests, desc total_requests
| limit 50
```

### 6. SaaS Application Usage Monitoring

Tracks SaaS application usage and potential shadow IT:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url" and is_saas_app = true
| comp count() as usage_count,
       count_distinct(source_ip) as user_count,
       sum(if(action = "allow", 1, 0)) as allowed_access,
       sum(if(action != "allow", 1, 0)) as blocked_access,
       earliest(_time) as first_seen,
       latest(_time) as last_seen by app, container_of_app, url_domain, app_category
| alter days_active = timestamp_diff(last_seen, first_seen, "DAY")
| alter approval_status = if(
    blocked_access = 0, "Approved/Unrestricted",
    blocked_access > allowed_access, "Mostly Blocked", 
    "Partially Restricted"
)
| sort desc usage_count
| limit 40
```

### 7. Encrypted Traffic Analysis

Analyzes HTTPS/encrypted connections for potential security insights:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter dest_port = 443 or protocol = "ssl"
| alter encryption_status = if(
    is_decrypted = true, "Decrypted",
    is_encrypted = true, "Encrypted - Not Decrypted",
    "Unknown/Unencrypted"
)
| comp count() as connection_count,
       count_distinct(url_domain) as unique_ssl_domains,
       count_distinct(source_ip) as users,
       avg(if(dest_port != null, dest_port, 443)) as avg_port by encryption_status, url_category_list, action
| sort desc connection_count
| limit 30
```

### 8. Geographic and Time-based Analysis

Provides insights into URL access patterns by location and time:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| alter hour_of_day = extract_time(_time, "HOUR"),
       day_of_week = extract_time(_time, "DAYOFWEEK"),
       time_category = if(
           hour_of_day >= 9 and hour_of_day <= 17, "Business Hours",
           hour_of_day >= 18 and hour_of_day <= 23, "Evening",
           "Night/Early Morning"
       )
| comp count() as access_count,
       count_distinct(url_domain) as unique_domains,
       count_distinct(source_ip) as active_users by dest_location, source_location, time_category, url_category_list
| sort desc access_count
| limit 50
```

### 9. Anomaly Detection - Unusual Port Usage

Identifies non-standard port usage that might indicate suspicious activity:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter dest_port not in (80, 443, 8080, 8443)
| comp count() as unusual_port_count,
       count_distinct(source_ip) as users_affected,
       count_distinct(url_domain) as domains_accessed,
       values(app) as applications by dest_port, protocol, action
| sort desc unusual_port_count
| limit 25
```

### 10. Executive Summary Dashboard Query

Comprehensive overview for management reporting:

```xql
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 86400), "SECONDS")
| alter risk_category = if(
    action in ("block", "deny") or severity in ("Critical", "High"), "High Risk",
    action = "alert" or severity = "Medium", "Medium Risk",
    "Low Risk"
)
| comp count() as total_url_events,
       count_distinct(source_ip) as unique_users,
       count_distinct(url_domain) as unique_domains,
       count_distinct(app) as unique_applications,
       sum(if(action in ("block", "deny"), 1, 0)) as blocked_events,
       sum(if(is_saas_app = true, 1, 0)) as saas_events,
       count_distinct(url_category_list) as categories_accessed by risk_category
| alter block_percentage = multiply(divide(blocked_events, total_url_events), 100),
       saas_percentage = multiply(divide(saas_events, total_url_events), 100)
```

## Notes

- Replace `panw_ngfw_url_raw` with your actual NGFW dataset name
- Adjust time filters and thresholds based on your environment
- Some fields may vary depending on your NGFW version - validate field names before use
