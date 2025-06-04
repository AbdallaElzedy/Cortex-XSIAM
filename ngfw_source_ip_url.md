```XQL
// ===================================================================
// FOCUSED URL USAGE ANALYSIS - TOP SITES & SECURITY ALERTS
// ===================================================================
// Purpose: Most visited URLs 
// Author: Abdalla Elzedy - Security Engineer
// ===================================================================
dataset = panw_ngfw_url_raw
| filter log_type = "threat" and sub_type = "url"
| filter source_ip = "<source_ip>"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
// ===== CRITICAL ANALYSIS =====
| alter attention_flag = if(
           action in ("block", "deny"), "🚨 BLOCKED",
           url_category_list contains "malware" or url_category_list contains "phishing", "⚠️ MALICIOUS",
           url_category_list contains "proxy-avoidance-and-anonymizers", "⚠️ VPN/PROXY",
           url_category_list contains "gambling" or url_category_list contains "adult", "⚠️ POLICY_RISK",
           url_domain ~= ".*\\.tk$|.*\\.ml$|.*\\.ga$|.*\\.cf$", "⚠️ SUSPICIOUS_TLD",
           ""
       )
// ===== SUMMARIZE BY DOMAIN =====
| comp 
    // Usage Statistics
    count() as total_visits,
    count_distinct(format_timestamp("%Y-%m-%d", _time)) as days_used,
    earliest(_time) as first_visit,
    latest(_time) as last_visit,
    // Critical Security Info
    sum(if(action in ("block", "deny"), 1, 0)) as blocked_attempts,
    values(attention_flag) as security_flags,
    values(action) as actions_seen,
    // Context Information
    values(url_category_list) as categories,
    values(app) as applications_used
    by url_domain
// ===== FOCUS ON IMPORTANT SITES =====
| alter 
    usage_period = concat(
        format_timestamp("%Y-%m-%d %H:%M:%S", first_visit), 
        " to ", 
        format_timestamp("%Y-%m-%d %H:%M:%S", last_visit)
    ),
    attention_level = if(
        blocked_attempts > 0 or security_flags contains "🚨 BLOCKED", "🚨 IMMEDIATE ATTENTION",
        security_flags contains "⚠️ MALICIOUS" or security_flags contains "⚠️ VPN/PROXY", "⚠️ HIGH PRIORITY", 
        security_flags contains "⚠️ POLICY_RISK" or security_flags contains "⚠️ SUSPICIOUS_TLD", "⚠️ REVIEW NEEDED",
        total_visits > 100, "📊 HIGH USAGE",
        ""
    ),
    usage_summary = concat(
        to_string(total_visits), " visits over ", 
        to_string(days_used), " days"
    )
// ===== CLEAN OUTPUT =====
| fields 
    url_domain,
    attention_level,
    usage_summary,
    usage_period,
    blocked_attempts,
    total_visits,
    categories,
    applications_used
// ===== PRIORITIZE CRITICAL SITES =====
| sort desc blocked_attempts, desc total_visits
// ===== TOP 20 MOST IMPORTANT =====
| limit 20
```
