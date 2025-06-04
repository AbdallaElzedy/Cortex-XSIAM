```Cortex XSIAM XQL Query 
// ===================================================================
// FOCUSED USER ACTIVITY ANALYSIS - O365/AZURE AD
// ===================================================================
// Purpose: Deep dive analysis of a specific user's O365 login activities
// Author: Abdalla Elzedy - Security Engineer
// ===================================================================
dataset = msft_o365_azure_ad_raw
| filter UserId = "<UserId>"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
// ===== ACTIVITY CLASSIFICATION =====
| alter activity_timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
       activity_hour = extract_time(_time, "HOUR"),
       time_category = if(
           extract_time(_time, "HOUR") >= 9 and extract_time(_time, "HOUR") <= 17, "Business Hours",
           extract_time(_time, "HOUR") >= 18 and extract_time(_time, "HOUR") <= 23, "After Hours",
           "Night/Weekend"
       ),
// ===== SECURITY CLASSIFICATION =====
       security_event = if(
           Operation = "UserLoginFailed" and ResultStatus = "Failed", "🚨 LOGIN_FAILURE",
           Operation = "UserLoginFailed" and ResultStatus = "Success", "⚠️ UNUSUAL_LOGIN",
           Operation = "UserLoggedIn" and ResultStatus = "Success", "✅ SUCCESSFUL_LOGIN",
           Operation contains "password" or Operation contains "Password", "🔑 PASSWORD_CHANGE",
           Operation contains "role" or Operation contains "group", "👑 PRIVILEGE_ACTIVITY",
           Operation contains "device" or Operation contains "Device", "📱 DEVICE_ACTIVITY",
           "📋 OTHER_ACTIVITY"
       ),
// ===== NETWORK ANALYSIS =====
       location_type = if(
           incidr(ClientIP, "<your ip range>"), "Campus_NAT",
           incidr(ClientIP, "<your ip range>"), "Campus_Direct",
           "External_Location"
       )
// ===== USER BEHAVIOR ANALYSIS =====
| comp 
    // Activity Overview
    count() as total_activities,
    count_distinct(format_timestamp("%Y-%m-%d", _time)) as days_active,
    count_distinct(ClientIP) as unique_locations,
    count_distinct(ApplicationId) as unique_applications,
    earliest(_time) as first_activity,
    latest(_time) as last_activity,
    // Authentication Analysis
    sum(if(Operation = "UserLoginFailed" and ResultStatus = "Failed", 1, 0)) as failed_logins,
    sum(if(Operation = "UserLoginFailed" and ResultStatus = "Success", 1, 0)) as unusual_logins,
    sum(if(Operation = "UserLoggedIn" and ResultStatus = "Success", 1, 0)) as successful_logins,
    // Activity Patterns
    count_distinct(activity_hour) as active_hours,
    sum(if(time_category = "Business Hours", 1, 0)) as business_hours_activity,
    sum(if(time_category != "Business Hours", 1, 0)) as off_hours_activity,
    // Security Events
    sum(if(Operation contains "password", 1, 0)) as password_activities,
    sum(if(Operation contains "role" or Operation contains "group", 1, 0)) as privilege_activities,
    sum(if(Operation contains "device", 1, 0)) as device_activities,
    // Location Intelligence
    count_distinct(if(location_type = "External_Location", ClientIP, null)) as external_ips,
    values(ClientIP) as all_source_ips,
    values(location_type) as location_types,
    // Application Usage
    values(ApplicationId) as applications_accessed,
    values(Workload) as workloads_used,
    // Activity Details
    values(Operation) as operations_performed,
    values(security_event) as security_events,
    values(time_category) as activity_time_patterns,
    // Complete Timeline
    list(activity_timestamp) as activity_timeline,
    list(concat(Operation, " [", ResultStatus, "] from ", ClientIP)) as detailed_activities
    by security_event
// ===== BEHAVIORAL ANALYSIS =====
| alter 
    // Calculate patterns
    activity_span_days = timestamp_diff(last_activity, first_activity, "DAY"),
    avg_activities_per_day = if(
        timestamp_diff(last_activity, first_activity, "DAY") > 0,
        divide(total_activities, timestamp_diff(last_activity, first_activity, "DAY")),
        total_activities
    ),
    // Calculate ratios
    off_hours_ratio = if(
        total_activities > 0,
        multiply(divide(off_hours_activity, total_activities), 100),
        0
    ),
    failure_rate = if(
        add(failed_logins, successful_logins) > 0,
        multiply(divide(failed_logins, add(failed_logins, successful_logins)), 100),
        0
    ),
    // Risk indicators
    base_risk_score = add(
        add(
            failed_logins,                        // Each failed login = 1 point
            multiply(unusual_logins, 2)           // Each unusual login = 2 points
        ),
        multiply(external_ips, 3)                // Each external IP = 3 points
    )
| alter
    // Additional risk factors
    risk_indicators = add(
        base_risk_score,
        if(off_hours_ratio > 50, 5, 0)          // 5 points if >50% off-hours
    )
| alter
    // User behavior profile
    behavior_profile = if(
        failed_logins > 10, "🚨 AUTHENTICATION_ISSUES",
        unusual_logins > 5, "⚠️ UNUSUAL_PATTERNS",
        external_ips > 2, "🌍 EXTERNAL_ACCESS_USER",
        privilege_activities > 5, "👑 PRIVILEGED_USER",
        off_hours_ratio > 70, "🌙 OFF_HOURS_USER",
        "✅ NORMAL_USER"
    ),
    // Activity status
    activity_status = if(
        timestamp_diff(current_time(), last_activity, "HOUR") < 1, "🟢 ACTIVE_NOW",
        timestamp_diff(current_time(), last_activity, "HOUR") < 24, "🟡 RECENT_24H",
        timestamp_diff(current_time(), last_activity, "DAY") < 7, "🔵 THIS_WEEK",
        "⚪ HISTORICAL"
    )
// ===== INVESTIGATION SUMMARY =====
| alter 
    user_summary = concat(
        behavior_profile, " | ",
        "Risk: ", to_string(risk_indicators), " | ",
        "Off-hours: ", to_string(round(off_hours_ratio)), "% | ",
        "Status: ", activity_status
    ),
    activity_period = concat(
        format_timestamp("%Y-%m-%d %H:%M:%S", first_activity),
        " to ",
        format_timestamp("%Y-%m-%d %H:%M:%S", last_activity)
    )
// ===== FOCUSED OUTPUT =====
| fields 
    // Event Classification
    security_event,
    // Summary Intelligence
    user_summary, behavior_profile, risk_indicators,
    // Activity Overview
    total_activities, days_active, activity_span_days, avg_activities_per_day,
    activity_period, activity_status,
    // Authentication Intelligence
    failed_logins, unusual_logins, successful_logins, failure_rate,
    // Location & Access Intelligence
    unique_locations, external_ips, all_source_ips, location_types,
    // Activity Patterns
    active_hours, business_hours_activity, off_hours_activity, off_hours_ratio,
    activity_time_patterns,
    // Security Activities
    password_activities, privilege_activities, device_activities,
    // Application Usage
    unique_applications, applications_accessed, workloads_used,
    // Investigation Evidence
    operations_performed, security_events, activity_timeline, detailed_activities
// ===== SORT BY RISK =====
| sort desc risk_indicators, desc total_activities
// ===== SHOW ALL ACTIVITY TYPES =====
| limit 20
```
