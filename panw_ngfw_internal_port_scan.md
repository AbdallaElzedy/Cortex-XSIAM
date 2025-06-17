# XQL Internal Port Scanning Detection
This XQL query analyzes Palo Alto Networks NGFW threat logs to identify potential port scanning activity from internal hosts. It detects common scanning signatures like Nmap, Masscan, and generic port scans, then aggregates the activity by source IP with basic risk scoring based on scan volume, target diversity, and port types accessed. The query provides visibility into lateral movement and reconnaissance activities by categorizing scan directions (internal-to-internal, internal-to-external, external-to-internal) and analyzing firewall responses, though it has limitations including reliance on threat signature detection and potential false positives from legitimate network tools, requiring proper tuning for each environment.



``` Internal Port Scanning Detection - NGFW Threat Logs

// ===================================================================
// Internal Port Scanning Detection - NGFW Threat Logs
// ===================================================================
// Use Case: Detect internal hosts performing port scanning
// Focus: threat_name-based detection from NGFW threat logs
// Author: Abdalla Elzedy
// ===================================================================

dataset = panw_ngfw_threat_raw 
// | filter _time > to_timestamp(subtract(to_epoch(current_time()), 3600), "SECONDS") // Last 1 hour
| filter log_type = "threat" 
| filter threat_name in (
    "SCAN: TCP Port Scan",
    "SCAN: UDP Port Scan", 
    "Masscan Port Scanning Tool Detection",
    "SCAN: Nmap OS Detection",
    "SCAN: Nmap Script Scan",
    "SCAN: TCP SYN Scan",
    "SCAN: TCP Connect Scan",
    "SCAN: Stealth Port Scan",
    "SCAN: Intense Scan",
    "SCAN: Ping Sweep",
    "SCAN: Network Enumeration",
    "Port Scan",
    "Network Scan"
)

// ===== INTERNAL NETWORK CLASSIFICATION =====
| alter 
    source_network_type = if(
        incidr(source_ip, "10.0.0.0/8") or 
        incidr(source_ip, "172.16.0.0/12") or 
        incidr(source_ip, "192.168.0.0/16"), "INTERNAL",
        "EXTERNAL"
    ),
    dest_network_type = if(
        incidr(dest_ip, "10.0.0.0/8") or 
        incidr(dest_ip, "172.16.0.0/12") or 
        incidr(dest_ip, "192.168.0.0/16"), "INTERNAL", 
        "EXTERNAL"
    )

// ===== FOCUS ON INTERNAL SCANNING ONLY =====
| filter source_network_type = "INTERNAL" or dest_network_type = "INTERNAL"

// ===== SCAN PATTERN ANALYSIS =====
| alter 
    scan_direction = if(
        source_network_type = "INTERNAL" and dest_network_type = "INTERNAL", "🏠 INTERNAL_TO_INTERNAL",
        source_network_type = "INTERNAL" and dest_network_type = "EXTERNAL", "🌐 INTERNAL_TO_EXTERNAL", 
        source_network_type = "EXTERNAL" and dest_network_type = "INTERNAL", "🚨 EXTERNAL_TO_INTERNAL",
        "🟡 UNKNOWN_DIRECTION"
    ),
    scan_severity_level = if(
        severity = "Critical", "🚨 CRITICAL",
        severity = "High", "🔴 HIGH",
        severity = "Medium", "🟠 MEDIUM", 
        severity = "Low", "🟡 LOW",
        "⚪ UNKNOWN"
    ),
    scan_tool_type = if(
        threat_name contains "Masscan", "⚡ MASSCAN_TOOL",
        threat_name contains "Nmap", "🔍 NMAP_TOOL",
        threat_name contains "TCP", "🔗 TCP_SCAN",
        threat_name contains "UDP", "📡 UDP_SCAN",
        threat_name contains "Ping", "📶 PING_SWEEP",
        "🔧 OTHER_SCAN_TOOL"
    ),
    firewall_action_type = if(
        action = "drop", "🚫 DROPPED",
        action = "deny", "🚫 DENIED", 
        action = "allow", "✅ ALLOWED",
        action contains "reset", "🔄 RESET",
       action
    )

// ===== AGGREGATE SCANNING ACTIVITY =====
| comp 
    // Core scanning statistics
    count() as total_scan_detections,
    count_distinct(dest_ip) as unique_targets,
    count_distinct(dest_port) as unique_ports_scanned,
    count_distinct(threat_name) as scan_signature_types,
    count_distinct(session_id) as unique_sessions,
    earliest(_time) as first_scan_detection,
    latest(_time) as last_scan_detection,
    
    // Action analysis
    sum(if(action in ("allow","alert") , 1, 0)) as allowed_scans,
    sum(if(action in ("drop", "deny"), 1, 0)) as blocked_scans,
    sum(if(action contains "reset", 1, 0)) as reset_scans,
    
    // Severity breakdown
    sum(if(severity = "Critical", 1, 0)) as critical_detections,
    sum(if(severity = "High", 1, 0)) as high_detections, 
    sum(if(severity = "Medium", 1, 0)) as medium_detections,
    sum(if(severity = "Low", 1, 0)) as low_detections,
    
    // Port analysis
    sum(if(dest_port >= 1 and dest_port <= 1024, 1, 0)) as system_port_scans,
    sum(if(dest_port in (22, 23, 135, 445, 1433, 3389, 5432), 1, 0)) as admin_port_scans,
    sum(if(dest_port in (80, 443, 8080, 8443), 1, 0)) as web_port_scans,
    sum(if(dest_port in (1433, 1521, 3306, 5432, 27017), 1, 0)) as database_port_scans,
    
    // Time analysis
    count_distinct(format_timestamp("%Y-%m-%d", _time)) as scan_active_days,
    count_distinct(extract_time(_time, "HOUR")) as scan_active_hours,
    
    // Geographic analysis
    count_distinct(source_location) as source_countries,
    count_distinct(dest_location) as dest_countries,
    
    // Technical details
    values(scan_direction) as scan_directions,
    values(scan_severity_level) as severity_levels,
    values(scan_tool_type) as scanning_tools,
    values(firewall_action_type) as firewall_actions,
    values(threat_name) as threat_signatures,
    values(dest_ip) as target_hosts,
    values(dest_port) as ports_targeted,
    values(from_zone) as source_zones,
    values(to_zone) as destination_zones,
    values(rule_matched) as firewall_rules_hit,
    values(source_location) as source_locations,
    values(dest_location) as destination_locations,
    min(dest_port) as lowest_port_scanned,
    max(dest_port) as highest_port_scanned
    
    by source_ip

// ===== INTERNAL SCAN INTENSITY SCORING =====
| alter 
    scan_duration_minutes = round(divide(subtract(to_epoch(last_scan_detection), to_epoch(first_scan_detection)), 60))
    | alter scans_per_minute = if(scan_duration_minutes > 0, round(divide(total_scan_detections, scan_duration_minutes)), total_scan_detections),
    target_diversity = add(unique_targets, unique_ports_scanned),
    port_range_span = subtract(highest_port_scanned, lowest_port_scanned)

| alter internal_scan_risk_score = if(
    // Critical risk indicators
    allowed_scans > 50 and admin_port_scans > 20, 100,
    critical_detections > 0 and unique_targets > 10, 95,
    total_scan_detections > 500 and scans_per_minute > 10, 90,
    
    // High risk indicators
    unique_targets > 20 and unique_ports_scanned > 50, 85,
    admin_port_scans > 30 and database_port_scans > 10, 80,
    total_scan_detections > 200 and scan_duration_minutes <= 30, 75,
    
    // Medium risk indicators
    unique_targets > 10 and system_port_scans > 50, 70,
    total_scan_detections > 100 and unique_ports_scanned > 20, 65,
    web_port_scans > 20 and admin_port_scans > 10, 60,
    
    // Low risk indicators
    total_scan_detections > 50, 55,
    unique_targets > 5, 50,
    45
)

// ===== INTERNAL SCAN RISK CLASSIFICATION =====
| alter 
    internal_scan_threat_level = if(
        allowed_scans > 50 and admin_port_scans > 20, "🚨 CRITICAL: SUCCESSFUL ADMIN SCANNING",
        internal_scan_risk_score >= 95, "🚨 CRITICAL: ADVANCED INTERNAL SCANNING",
        internal_scan_risk_score >= 85, "🔴 SEVERE: HIGH-VOLUME INTERNAL SCANNING",
        internal_scan_risk_score >= 75, "🔴 HIGH: RAPID INTERNAL SCANNING",
        internal_scan_risk_score >= 65, "🟠 MODERATE: TARGETED INTERNAL SCANNING",
        internal_scan_risk_score >= 55, "🟡 ELEVATED: DETECTED INTERNAL SCANNING",
        "🟢 LOW: MINIMAL SCANNING ACTIVITY"
    ),
    scan_timeframe = concat(
        format_timestamp("%Y-%m-%d %H:%M:%S", first_scan_detection),
        " → ",
        format_timestamp("%Y-%m-%d %H:%M:%S", last_scan_detection)
    )

// =====  INTERNAL SCAN PROFILE =====
| alter 
    scan_activity_summary = concat(
        to_string(total_scan_detections), " detections | ",
        to_string(unique_targets), " targets | ",
        to_string(unique_ports_scanned), " ports | ",
        to_string(scan_signature_types), " signatures"
    ),
    firewall_response_summary = concat(
        "Allowed: ", to_string(allowed_scans), " | ",
        "Blocked: ", to_string(blocked_scans), " | ",
        "Reset: ", to_string(reset_scans), " | ",
        "Risk Score: ", to_string(internal_scan_risk_score)
    ),
    severity_breakdown = concat(
        "Critical: ", to_string(critical_detections), " | ",
        "High: ", to_string(high_detections), " | ",
        "Medium: ", to_string(medium_detections), " | ", 
        "Low: ", to_string(low_detections)
    ),
    port_targeting_analysis = concat(
        "System: ", to_string(system_port_scans), " | ",
        "Admin: ", to_string(admin_port_scans), " | ",
        "Web: ", to_string(web_port_scans), " | ",
        "DB: ", to_string(database_port_scans)
    ),
    scan_performance_metrics = concat(
        "Duration: ", to_string(scan_duration_minutes), "min | ",
        "Rate: ", to_string(scans_per_minute), "/min | ",
        "Range: ", to_string(lowest_port_scanned), "-", to_string(highest_port_scanned), " | ",
        "Diversity: ", to_string(target_diversity)
    )

// ===== FINAL RESULTS FOR ANALYSIS =====
| fields 
    source_ip,
    target_hosts,
    internal_scan_threat_level,
    scan_directions,
    threat_signatures,
    firewall_actions,
    ports_targeted,
    scan_activity_summary,
    firewall_response_summary,
    severity_breakdown,
    port_targeting_analysis,
    scan_performance_metrics,
    scan_timeframe,
    total_scan_detections,
    allowed_scans,
    blocked_scans,
    unique_targets,
    unique_ports_scanned,
    scans_per_minute,
    internal_scan_risk_score,
    scanning_tools,
    source_zones,
    destination_zones,
    firewall_rules_hit

// ===== PRIORITIZE HIGHEST RISK INTERNAL SCANNERS =====
| sort desc internal_scan_risk_score, desc allowed_scans, desc total_scan_detections

