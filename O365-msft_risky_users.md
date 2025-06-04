```Cortex XSIAM XQL Query
// ===================================================================
// O365/AZURE AD SECURITY ANALYSIS QUERY
// ===================================================================
// Purpose: Detect authentication threats, suspicious activities, and user behavior
// Author: Abdalla Elzedy - Security Engineer
// Focus: Authentication security, privilege escalation, suspicious activities
// ===================================================================
dataset = msft_o365_azure_ad_raw
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 86400), "SECONDS")
// ===== SECURITY ENRICHMENT =====
| alter activity_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
       activity_hour = extract_time(_time, "HOUR"),
       activity_date = format_timestamp("%Y-%m-%d", _time),
       time_category = if(
           extract_time(_time, "HOUR") >= 9 and extract_time(_time, "HOUR") <= 17, "Business Hours",
           extract_time(_time, "HOUR") >= 18 and extract_time(_time, "HOUR") <= 23, "After Hours",
           "Night/Weekend"
       ),
// ===== THREAT CLASSIFICATION =====
       threat_level = if(
           Operation = "UserLoginFailed" and ResultStatus = "Failed", "🚨 FAILED_LOGIN",
           Operation = "UserLoginFailed" and ResultStatus = "Success", "⚠️ ANOMALOUS_LOGIN",
           Operation contains "password" or Operation contains "Password", "🔑 PASSWORD_ACTIVITY",
           Operation contains "role" or Operation contains "group", "👑 PRIVILEGE_CHANGE",
           Operation contains "Add" and Operation contains "user", "👤 USER_CREATION",
           Operation contains "Disable" or Operation contains "Delete", "🗑️ ACCOUNT_DISABLE",
           Operation = "UserLoggedIn" and ResultStatus = "Success", "✅ SUCCESSFUL_LOGIN",
           ""
       ),
// ===== NETWORK ANALYSIS =====
       ip_classification = if(
           incidr(ClientIP, "140.180.240.0/24"), "Internal_NAT",
           incidr(ClientIP, "128.112.0.0/16,165.1.0.0/16,137.83.0.0/16"), "Campus_Network",
           incidr(ClientIP, "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"), "Private_Network",
           "External_Internet"
       )
// ===== COMPREHENSIVE SECURITY ANALYSIS =====
| comp 
    // Activity Summary
    count() as total_activities,
    count_distinct(activity_date) as days_active,
    count_distinct(UserId) as unique_users,
    count_distinct(ClientIP) as unique_ips,
    earliest(_time) as first_activity,
    latest(_time) as last_activity,
    // Authentication Intelligence
    sum(if(Operation = "UserLoginFailed" and ResultStatus = "Failed", 1, 0)) as failed_logins,
    sum(if(Operation = "UserLoginFailed" and ResultStatus = "Success", 1, 0)) as anomalous_logins,
    sum(if(Operation = "UserLoggedIn" and ResultStatus = "Success", 1, 0)) as successful_logins,
    // Privilege & Administrative Activity
    sum(if(Operation contains "role" or Operation contains "group", 1, 0)) as privilege_changes,
    sum(if(Operation contains "Add user" or Operation contains "Delete", 1, 0)) as account_changes,
    sum(if(Operation contains "password", 1, 0)) as password_activities,
    // Risk Indicators
    count_distinct(if(ip_classification = "External_Internet", ClientIP, null)) as external_ips,
    count_distinct(if(time_category != "Business Hours", UserId, null)) as off_hours_users,
    // Technical Intelligence
    values(ip_classification) as network_sources,
    // Geographic Intelligence
    values(ClientIP) as source_ips,
    values(time_category) as activity_patterns,
    // Evidence
    list(activity_timestamp) as activity_timeline,
    list(concat(Operation, " [", ResultStatus, "]")) as operation_details
    // Group by critical dimensions
    by threat_level,
       ip_classification, 
       UserId
// ===== RISK SCORING =====
| alter 
    // Calculate activity patterns
    activity_duration_days = timestamp_diff(last_activity, first_activity, "DAY"),
    avg_activities_per_day = if(
        timestamp_diff(last_activity, first_activity, "DAY") > 0,
        divide(total_activities, timestamp_diff(last_activity, first_activity, "DAY")),
        total_activities
    ),
    // Risk scoring algorithm
    risk_score = add(
        add(
            add(
                multiply(failed_logins, 5),           // 5 points per failed login
                multiply(anomalous_logins, 10)        // 10 points per anomalous login
            ),
            add(
                multiply(privilege_changes, 15),      // 15 points per privilege change
                multiply(account_changes, 20)         // 20 points per account change
            )
        ),
        add(
            multiply(external_ips, 8),               // 8 points per external IP
            multiply(off_hours_users, 3)             // 3 points per off-hours user
        )
    ),
    // Failure rate calculation
    failure_rate = if(
        add(failed_logins, successful_logins) > 0,
        multiply(divide(failed_logins, add(failed_logins, successful_logins)), 100),
        0
    )
| alter
    // User risk classification
    user_risk_profile = if(
        failed_logins > 50, "🚨 BRUTE_FORCE_TARGET",
        anomalous_logins > 20, "⚠️ ANOMALOUS_BEHAVIOR",
        privilege_changes > 10, "👑 HIGH_PRIVILEGE_USER",
        account_changes > 5, "👤 ACCOUNT_MANAGER",
        external_ips > 3, "🌍 EXTERNAL_ACCESS_USER",
        failure_rate > 50, "🔒 AUTHENTICATION_ISSUES",
        "✅ NORMAL_USER"
    ),
    // Activity recency
    activity_recency = if(
        timestamp_diff(current_time(), last_activity, "HOUR") < 1, "ACTIVE_NOW",
        timestamp_diff(current_time(), last_activity, "HOUR") < 24, "RECENT_24H",
        "HISTORICAL"
    )
// ===== INVESTIGATION PRIORITY =====
| alter 
    investigation_summary = concat(
        user_risk_profile, " | ",
        "Risk Score: ", to_string(risk_score), " | ",
        "Failure Rate: ", to_string(round(failure_rate)), "% | ",
        "Status: ", activity_recency
    ),
    first_activity_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", first_activity),
    last_activity_formatted = format_timestamp("%Y-%m-%d %H:%M:%S", last_activity)
// ===== PRIORITIZED OUTPUT =====
| fields 
    // Primary Identity
    UserId, threat_level, ip_classification,
    // Investigation Summary
    investigation_summary, risk_score, user_risk_profile,
    // Activity Overview
    total_activities, days_active, activity_duration_days, avg_activities_per_day,
    first_activity_formatted, last_activity_formatted, activity_recency,
    // Authentication Intelligence
    failed_logins, anomalous_logins, successful_logins, failure_rate,
    // Security Intelligence
    privilege_changes, account_changes, password_activities,
    external_ips, off_hours_users,
    // Technical Intelligence
    unique_ips, network_sources,
    // Behavioral Intelligence
    activity_patterns, source_ips,
    // Forensic Evidence
    activity_timeline, operation_details
// ===== SORT BY INVESTIGATION PRIORITY =====
| sort desc risk_score, desc failed_logins, desc anomalous_logins
// ===== TOP PRIORITY CASES =====
| limit 100
```
