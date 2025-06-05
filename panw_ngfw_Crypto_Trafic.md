```Cortex XSIAM PaloAlto Crypto Traffic
// ===================================================================
// Monitor Crypto traffic
// ===================================================================
// Use Case:Threat hunting
// Author: Abdalla Elzedy
// ===================================================================
dataset = panw_ngfw_threat_raw 
| filter threat_name contains "crypto" or threat_name contains "mine" or threat_name contains "minin"
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
// ===== CRYPTOMINER THREAT ANALYSIS =====
| alter mining_risk_level = if(
           action in ("block", "deny", "drop"), "🚨 BLOCKED_MINING",
           action = "reset-both", "🔴 CONNECTION_RESET", 
           action = "reset-client", "🟠 CLIENT_RESET",
           action = "reset-server", "🟠 SERVER_RESET",
           action = "allow", "⚠️ ALLOWED_MINING",
           "🟡 OTHER_ACTION"
       ),
       mining_protocol_type = if(
           // Stratum Protocols (V1 & V2)
           app = "stratum-mining-protocol" or tunneled_app = "stratum-mining-protocol" or 
           app = "stratum-v2" or tunneled_app = "stratum-v2", "⛏️ STRATUM_PROTOCOL",
           
           // Advanced Mining Applications
           app contains "mining" or tunneled_app contains "mining" or
           app in ("xmrig", "t-rex", "cgminer", "bfgminer", "nicehash", "phoenixminer", "claymore", "gminer", "nbminer", "teamredminer", "lolminer", "trex", "miniZ", "wildrig", "xmr-stak", "cryptodredge", "z-enemy", "bminer", "ewbf", "dstm", "ccminer", "ethminer", "cryptonight", "randomx") or
           tunneled_app in ("xmrig", "t-rex", "cgminer", "bfgminer", "nicehash", "phoenixminer", "claymore", "gminer", "nbminer", "teamredminer", "lolminer", "trex", "miniZ", "wildrig", "xmr-stak", "cryptodredge", "z-enemy", "bminer", "ewbf", "dstm", "ccminer", "ethminer", "cryptonight", "randomx"), "⛏️ MINING_APP",
           
           // Comprehensive Mining Ports
           dest_port in (25, 80, 443, 1300, 1301, 1314, 3333, 3334, 3335, 3336, 4444, 5555, 5556, 5588, 5730, 6099, 6666, 7777, 7778, 8000, 8001, 8008, 8118, 8332, 8333, 8888, 8899, 9000, 9332, 9999, 14433, 14444, 18080, 30303, 45560, 45700), "⛏️ MINING_PORT",
           
           // Blockchain Node Ports
           dest_port in (8545, 8546, 30303, 9000, 13000, 12000, 26656, 26657, 1317, 9090, 4001, 4002, 8080), "🔗 BLOCKCHAIN_NODE",
           
           // Browser Mining & WebAssembly
           app contains "webassembly" or app contains "wasm" or app contains "coinhive" or app contains "coinimp" or app contains "jsecoin" or app contains "cryptoloot", "🌐 BROWSER_MINING",
           
           // Proof-of-Stake Protocols
           dest_port in (9000, 12000, 13000) and (app contains "beacon" or app contains "validator" or app contains "consensus"), "🔒 POS_STAKING",
           
           // Privacy Coin Protocols
           dest_port = 18080 or app contains "monero" or app contains "zcash" or app contains "dash" or app contains "grin", "🔐 PRIVACY_COIN",
           
           "🌐 OTHER_CRYPTO"
       ),
       geographic_risk = if(
           dest_location in ("CN", "RU", "KP", "IR"), "🚩 HIGH_RISK_MINING_POOL",
           source_location in ("CN", "RU", "KP", "IR"), "🚩 HIGH_RISK_SOURCE",
           source_location != dest_location, "🌍 INTERNATIONAL_MINING",
           "🏠 DOMESTIC"
       )
// ===== AGGREGATE BY SOURCE IP =====
| comp 
    // Core Mining Statistics
    count() as total_mining_threats,
    count_distinct(dest_ip) as unique_mining_destinations,
    count_distinct(dest_port) as unique_mining_ports,
    count_distinct(threat_name) as unique_threat_signatures,
    earliest(_time) as first_mining_activity,
    latest(_time) as last_mining_activity,
    // Action Analysis
    sum(if(action in ("block", "deny", "drop"), 1, 0)) as blocked_mining_attempts,
    sum(if(action = "reset-both", 1, 0)) as reset_both_connections,
    sum(if(action = "allow", 1, 0)) as allowed_mining_attempts,
    // Activity Patterns
    count_distinct(format_timestamp("%Y-%m-%d", _time)) as mining_active_days,
    count_distinct(extract_time(_time, "HOUR")) as mining_active_hours,
    count_distinct(session_id) as unique_mining_sessions,
    // Protocol & Application Analysis
    sum(if(app = "stratum-mining-protocol" or tunneled_app = "stratum-mining-protocol", 1, 0)) as stratum_protocol_detections,
    count_distinct(app) as mining_applications,
    count_distinct(tunneled_app) as tunneled_mining_apps,
    // Geographic Analysis
    count_distinct(source_location) as source_countries,
    count_distinct(dest_location) as dest_countries,
    // Security Severity
    sum(if(severity = "Critical", 1, 0)) as critical_threats,
    sum(if(severity = "High", 1, 0)) as high_threats,
    sum(if(severity = "Medium", 1, 0)) as medium_threats,
    sum(if(severity = "Low", 1, 0)) as low_threats,
    // Technical Details
    values(mining_risk_level) as risk_indicators,
    values(mining_protocol_type) as protocol_types,
    values(geographic_risk) as geographic_flags,
    values(threat_name) as threat_signatures,
    values(dest_ip) as mining_destinations,
    values(dest_port) as mining_ports_used,
    values(app) as applications_detected,
    values(tunneled_app) as tunneled_apps_detected,
    values(source_location) as source_locations,
    values(dest_location) as destination_locations,
    values(action) as actions_taken
    by source_ip
// ===== MINING THREAT INTENSITY SCORING =====
| alter 
    mining_persistence = round(divide(total_mining_threats, mining_active_days)),
    mining_diversity = add(unique_mining_destinations , add( unique_threat_signatures,unique_mining_ports) )
| alter mining_intensity_score = if(
        allowed_mining_attempts > 100, 100,
        blocked_mining_attempts > 500 or critical_threats > 0, 95,
        total_mining_threats > 1000 and unique_mining_destinations > 10, 90,
        stratum_protocol_detections > 100, 85,
        total_mining_threats > 500 and mining_active_days > 5, 80,
        total_mining_threats > 200 and unique_mining_destinations > 5, 75,
        total_mining_threats > 100, 70,
        total_mining_threats > 50, 60,
        total_mining_threats > 20, 50,
        40
    )
// ===== CRYPTOMINER RISK CLASSIFICATION =====
| alter 
    cryptominer_risk_level = if(
        allowed_mining_attempts > 50, "🚨 ACTIVE CRYPTOMINING ALLOWED",
        critical_threats > 0, "🚨 CRITICAL CRYPTOMINER THREATS",
        mining_intensity_score >= 95, "🔴 SEVERE CRYPTOMINING ACTIVITY",
        mining_intensity_score >= 85, "🔴 HIGH CRYPTOMINING ACTIVITY",
        mining_intensity_score >= 75, "🟠 MODERATE CRYPTOMINING ACTIVITY",
        mining_intensity_score >= 60, "🟡 DETECTED CRYPTOMINING ATTEMPTS",
        "🟢 LOW CRYPTOMINING SIGNALS"
    ),
    activity_timeframe = concat(
        format_timestamp("%Y-%m-%d %H:%M", first_mining_activity),
        " → ",
        format_timestamp("%Y-%m-%d %H:%M", last_mining_activity)
    )
// ===== COMPREHENSIVE MINING PROFILE =====
| alter 
    mining_threat_summary = concat(
        to_string(total_mining_threats), " threats | ",
        to_string(unique_mining_destinations), " destinations | ",
        to_string(mining_active_days), " days | ",
        to_string(unique_mining_sessions), " sessions"
    ),
    security_action_summary = concat(
        "Blocked: ", to_string(blocked_mining_attempts), " | ",
        "Allowed: ", to_string(allowed_mining_attempts), " | ",
        "Reset: ", to_string(reset_both_connections), " | ",
        "Score: ", to_string(mining_intensity_score)
    ),
    threat_severity_breakdown = concat(
        "Critical: ", to_string(critical_threats), " | ",
        "High: ", to_string(high_threats), " | ",
        "Medium: ", to_string(medium_threats), " | ",
        "Low: ", to_string(low_threats)
    ),
    mining_analysis = concat(
        "Persistence: ", to_string(mining_persistence), "/day | ",
        "Diversity: ", to_string(mining_diversity), " | ",
        "Stratum: ", to_string(stratum_protocol_detections)
    )
// ===== FINAL OUTPUT FOR ANALYSIS =====
| fields 
    source_ip,
    mining_destinations,
    threat_signatures,
    cryptominer_risk_level,
    risk_indicators,
    mining_threat_summary,
    security_action_summary,
    threat_severity_breakdown,
    mining_analysis,
    activity_timeframe,
    total_mining_threats,
    allowed_mining_attempts,
    blocked_mining_attempts,
    mining_active_days,
    stratum_protocol_detections,
    protocol_types,
    geographic_flags,
    mining_ports_used,
    source_locations,
    destination_locations,
    actions_taken
// ===== PRIORITIZE HIGH-RISK CRYPTOMINERS =====
| sort desc allowed_mining_attempts, desc total_mining_threats
// ===== TOP 25 CRYPTOMINING COMMUNICATORS =====
| limit 25
```
