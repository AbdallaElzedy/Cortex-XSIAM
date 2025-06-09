```Cortex XDR Powershell Patterns
// =====  THREAT HUNTING: PowerShell =====
dataset = xdr_data
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 86400), "SECONDS") // Last 24 hours

// ===== DETECT SUSPICIOUS PROCESS CHAINS =====
| filter actor_process_image_name in (
    "powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "forfiles.exe", "schtasks.exe", "at.exe", "sc.exe", "net.exe", "netsh.exe",
    "whoami.exe", "nltest.exe", "dsquery.exe", "ldifde.exe", "csvde.exe"
) or action_process_image_name in (
    "powershell.exe", "cmd.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
    "forfiles.exe", "schtasks.exe", "at.exe", "sc.exe", "net.exe", "netsh.exe",
    "whoami.exe", "nltest.exe", "dsquery.exe", "ldifde.exe", "csvde.exe"
)


// ===== EXCLUDE PATTERNS =====
| filter not (
    // Exclude legitimate system paths and operations
    actor_process_command_line ~= ".*C:\\\\Program Files.*" or
    actor_process_command_line ~= ".*C:\\\\Windows\\\\System32.*" and actor_process_command_line ~= ".*Get-WmiObject.*Win32_.*" or
    actor_process_command_line ~= ".*microsoft.*" or
    actor_process_command_line ~= ".*windows update.*" or
    // Exclude simple administrative commands without suspicious patterns
    actor_process_command_line = "net  localgroup Administrators " or
    actor_process_command_line ~= ".*net.*localgroup.*" and not actor_process_command_line ~= ".*(add|/add|domain).*" or
    // Exclude simple file downloads without suspicious characteristics
    actor_process_command_line ~= ".*download_latest\.ps1.*" and not actor_process_command_line ~= ".*(WindowStyle|Hidden|bypass.*hidden).*" or
    actor_process_command_line ~= ".*chrome_download_latest\.ps1.*" and not actor_process_command_line ~= ".*(WindowStyle|Hidden|bypass.*hidden).*"
)



// ===== HIGH-FIDELITY THREAT DETECTION =====
| alter threat_category = if(
    // 🚨 CRITICAL: Base64 Encoded Commands (High Confidence Malicious)
    actor_process_command_line ~= ".*-encodedCommand.*[A-Za-z0-9+/=]{20,}.*" or
    action_process_image_command_line ~= ".*-encodedCommand.*[A-Za-z0-9+/=]{20,}.*",
    "🚨 ENCODED_EXECUTION",
    
    // 🔴 HIGH: Network Download & Execute
    actor_process_command_line ~= ".*certutil.*-urlcache.*-split.*-f.*http.*" or
    actor_process_command_line ~= ".*bitsadmin.*\/transfer.*http.*" or
    actor_process_command_line ~= ".*powershell.*(IEX|Invoke-Expression).*(New-Object.*Net\.WebClient|DownloadString).*" or
    actor_process_command_line ~= ".*powershell.*Invoke-WebRequest.*-OutFile.*\.(exe|bat|ps1|vbs).*" or
    action_process_image_command_line ~= ".*certutil.*-urlcache.*-split.*-f.*http.*",
    "🔴 DOWNLOAD_EXECUTE",
    
    // 🟠 MEDIUM: Advanced Reconnaissance  
    actor_process_command_line ~= ".*whoami.*\/all.*" or
    actor_process_command_line ~= ".*net.*(user|group).*(\/domain|domain).*" or
    actor_process_command_line ~= ".*nltest.*\/domain_trusts.*" or
    actor_process_command_line ~= ".*wmic.*process.*list.*full.*" or
    actor_process_command_line ~= ".*dsquery.*computer.*" or
    action_process_image_command_line ~= ".*whoami.*\/all.*",
    "🟠 RECONNAISSANCE",
    
    // 🟡 MEDIUM: Sophisticated Defense Evasion
    actor_process_command_line ~= ".*rundll32.*javascript:.*" or
    actor_process_command_line ~= ".*regsvr32.*\/s.*\/n.*\/u.*\/i.*scrobj\.dll.*" or
    actor_process_command_line ~= ".*mshta.*vbscript:.*" or
    actor_process_command_line ~= ".*powershell.*-ExecutionPolicy.*Bypass.*(WindowStyle.*Hidden|IEX|Invoke-Expression).*" or
    actor_process_command_line ~= ".*powershell.*(WindowStyle.*Hidden|Hidden.*WindowStyle).*-ExecutionPolicy.*Bypass.*" or
    action_process_image_command_line ~= ".*rundll32.*javascript:.*",
    "🟡 DEFENSE_EVASION",
    
    // 🔵 LOW-MEDIUM: Persistence & Lateral Movement
    actor_process_command_line ~= ".*schtasks.*\/create.*(\/ru.*system|\/sc.*onstart).*" or
    actor_process_command_line ~= ".*sc.*create.*binpath.*" or
    actor_process_command_line ~= ".*net.*use.*\$.*\/user.*" or
    actor_process_command_line ~= ".*wmic.*\/node.*process.*call.*create.*" or
    action_process_image_command_line ~= ".*schtasks.*\/create.*(\/ru.*system|\/sc.*onstart).*",
    "🔵 PERSISTENCE_LATERAL",
    
    "⚪ BENIGN"
)

// ===== ENHANCED RISK SCORING =====
| alter 
    base_risk_score = if(
        threat_category = "🚨 ENCODED_EXECUTION", 95,
        threat_category = "🔴 DOWNLOAD_EXECUTE", 85,
        threat_category = "🟠 RECONNAISSANCE", 70,
        threat_category = "🟡 DEFENSE_EVASION", 75,
        threat_category = "🔵 PERSISTENCE_LATERAL", 65,
        10
    ),
    // Boost risk for system account usage
    system_account_boost = if(actor_effective_username ~= ".*SYSTEM.*", 10, 0),
    // Boost risk for hidden window execution
    stealth_boost = if(actor_process_command_line ~= ".*(WindowStyle.*Hidden|Hidden.*WindowStyle).*", 15, 0),
    // Boost risk for bypassing execution policy
    bypass_boost = if(actor_process_command_line ~= ".*-ExecutionPolicy.*Bypass.*", 8, 0)

| alter final_risk_score = add(base_risk_score , add( system_account_boost , add (stealth_boost, bypass_boost)))

// ===== FILTER HIGH-CONFIDENCE THREATS =====
| filter threat_category != "⚪ BENIGN" and final_risk_score >= 60

// ===== PREPARE FIELDS FOR TRANSACTION ANALYSIS =====
| fields _time, agent_hostname, agent_id, 
         actor_process_image_name, actor_process_command_line, actor_process_os_pid,
         action_process_image_name, action_process_image_command_line, action_process_os_pid,
         actor_effective_username, actor_causality_id, causality_actor_process_os_pid,
         threat_category, final_risk_score, event_type, event_sub_type

// =====  CHAIN GROUPING =====
| transaction agent_hostname, actor_causality_id span=2H maxevents=50

// =====  THREAT ANALYSIS =====
| alter 
    attack_duration_minutes = round(divide(_duration, 60)),
    attack_complexity = if(
        _num_of_rows > 15 and _duration > 7200, "🚨 Take_a_look",
        _num_of_rows > 8 and _duration > 3600, "🔴 Interesting", 
        _num_of_rows > 4 and _duration > 1800, "🟠 Might_be_interesting",
        _num_of_rows > 2, "🟡 SUSPICIOUS_BEHAVIOR",
        "🟢 ISOLATED_EVENT"
    ),
    // Enhanced timeline with duration context
    attack_timeline = concat(
        format_timestamp("%m/%d %H:%M:%S", _start_time), " → ",
        format_timestamp("%m/%d %H:%M:%S", _end_time),
        " (", to_string(round(divide(_duration, 60))), "min)"
    )

// ===== THREAT INTELLIGENCE EXTRACTION =====
| alter 
    // Extract ALL commands from the transaction, then get distinct ones
    all_commands_array = arraymap(_raw, json_extract_scalar("@element", "$.actor_process_command_line"))
    // Get distinct commands only (removes duplicates)  
 | alter    distinct_commands_array = arraydistinct(all_commands_array)
    // Now extract up to 4 distinct sample commands
   | alter  sample_command_1 = if(array_length(distinct_commands_array) >= 1, arrayindex(distinct_commands_array, 0), null),
    sample_command_2 = if(array_length(distinct_commands_array) >= 2, arrayindex(distinct_commands_array, 1), null), 
    sample_command_3 = if(array_length(distinct_commands_array) >= 3, arrayindex(distinct_commands_array, 2), null),
    sample_command_4 = if(array_length(distinct_commands_array) >= 4, arrayindex(distinct_commands_array, 3), null),
    // Calculate how many unique commands we actually have
    total_distinct_commands = array_length(distinct_commands_array),
    primary_user = json_extract_scalar(arrayindex(_raw, 0), "$.actor_effective_username"),
    primary_threat = json_extract_scalar(arrayindex(_raw, 0), "$.threat_category"),
    max_risk_score = json_extract_scalar(arrayindex(_raw, 0), "$.final_risk_score")




// ===== COMMAND ANALYSIS & BASE64 DECODING =====
| alter
    // Check ALL distinct commands for base64 encoding, not just the first one
    encoded_command_array = if(
        sample_command_1 ~= "(?i).*-encodedcommand.*",
        regextract(sample_command_1, "(?i)-encodedCommand\s+([A-Za-z0-9+\=]+)"),
        sample_command_2 ~= "(?i).*-encodedcommand.*",
        regextract(sample_command_2, "(?i)-encodedCommand\s+([A-Za-z0-9+\=]+)"),
        sample_command_3 ~= "(?i).*-encodedcommand.*",
        regextract(sample_command_3, "(?i)-encodedCommand\s+([A-Za-z0-9+\=]+)"),
        sample_command_4 ~= "(?i).*-encodedcommand.*",
        regextract(sample_command_4, "(?i)-encodedCommand\s+([A-Za-z0-9+\=]+)"),
        null
    ),
    // Store which command contained the encoding
    encoded_command_source = if(
        sample_command_1 ~= "(?i).*-encodedcommand.*", "sample_command_1",
        sample_command_2 ~= "(?i).*-encodedcommand.*", "sample_command_2", 
        sample_command_3 ~= "(?i).*-encodedcommand.*", "sample_command_3",
        sample_command_4 ~= "(?i).*-encodedcommand.*", "sample_command_4",
        null
    )
    | alter encoded_command = if(
        encoded_command_array != null and array_length(encoded_command_array) > 0,
        arrayindex(encoded_command_array, 0),
        null
    )
    // DECODE BASE64 COMMANDS FOR ANALYSIS
  | alter decoded_command = if(
        encoded_command != null,
        replace(convert_from_base_64(encoded_command), "\u0000", ""),
        null
    ),
    // Extract key file names and paths from ALL distinct commands
    suspicious_files_array = regextract(coalesce(arraystring(distinct_commands_array, " "), ""), "([^\\\\\\s]+\\.(?:ps1|bat|exe|vbs|js))")
 | alter suspicious_files = if(
        suspicious_files_array != null and array_length(suspicious_files_array) > 0,
        arraydistinct(suspicious_files_array),
        null
    )



// ===== UNIQUE THREAT & USER ANALYSIS =====
| alter 
    threat_types_array = arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.threat_category"))),
    users_array = arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.actor_effective_username"))),
    unique_threat_count = array_length(arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.threat_category")))),
    unique_user_count = array_length(arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.actor_effective_username")))),
    threat_diversity = arraystring(arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.threat_category"))), " + "),
    user_context = arraystring(arraydistinct(arraymap(_raw, json_extract_scalar("@element", "$.actor_effective_username"))), " | ")

| alter command_uniqueness = if(
    total_distinct_commands = 1 and _num_of_rows > 1,
    "🔁 REPEATED_IDENTICAL",
    total_distinct_commands > 5,
    "🔀 HIGHLY_DIVERSE",
    total_distinct_commands > 2,
    "🔀 DIVERSE_COMMANDS", 
    "🔸 MINIMAL_ACTIVITY"
)


// ===== THREAT HUNTER SUMMARY =====
| alter
    // Calculate average risk across all events
    avg_risk_score = round(to_number(max_risk_score))
    // Create actionable threat summary
| alter threat_summary = concat(
    "🎯 ", to_string(unique_threat_count), " tactics | ",
    "💻 ", to_string(total_distinct_commands), " distinct cmds | ",
    "⚡ ", to_string(_num_of_rows), " events | ",
    "⏱️ ", to_string(attack_duration_minutes), "min | ",
    "🎲 Risk: ", to_string(avg_risk_score), "/100"
),
    // Create investigation priorities
    investigation_priority = if(
        decoded_command != null, "🚨 Encoded PowerShell (DECODED)",
        encoded_command != null, "🚨 Encoded PowerShell",
        threat_diversity ~= ".*ENCODED_EXECUTION.*", "🚨 Code Execution",
        threat_diversity ~= ".*DOWNLOAD_EXECUTE.*", "🔴 HIGH - Network Activity", 
        unique_threat_count > 2 and _num_of_rows > 10, "🟠 MEDIUM - Chain",
        command_uniqueness = "🔀 DIVERSE_COMMANDS", "🟡 LOW-MEDIUM - Investigate Pattern",
        "🟢 LOW - Monitor"
    ),
    // Enhanced command preview with decoded content
command_preview = if(
        decoded_command != null,
        concat("🔓 DECODED: ", decoded_command, " | SOURCE: ", encoded_command_source, " | ORIGINAL: ", 
               if(encoded_command_source = "sample_command_1", coalesce(sample_command_1, "No command"),
                  encoded_command_source = "sample_command_2", coalesce(sample_command_2, "No command"),
                  encoded_command_source = "sample_command_3", coalesce(sample_command_3, "No command"),
                  coalesce(sample_command_4, "No command"))),
        suspicious_files != null and array_length(suspicious_files) > 0,
        concat("📁 FILES: ", arraystring(suspicious_files, ", "), " | DISTINCT_CMDS: ", to_string(total_distinct_commands)),
        concat("💻 DISTINCT_CMDS: ", to_string(total_distinct_commands), " | FIRST_CMD: ", coalesce(sample_command_1, "No command"))
    )


// ===== HUNTER-READY OUTPUT =====
| fields 
    // Core identification
    agent_hostname, investigation_priority, threat_summary, 
    attack_timeline, command_uniqueness,
    // Threat context
    primary_threat, threat_diversity, user_context,
    // Evidence
    command_preview, encoded_command, decoded_command,
    sample_command_1, sample_command_2, sample_command_3,sample_command_4,
    // Metrics for analysis
    unique_threat_count, unique_user_count, avg_risk_score,
    attack_duration_minutes, _num_of_rows, _transaction_id,
    // Raw timestamps for correlation
    _start_time, _end_time

// ===== PRIORITIZATION =====
| sort desc avg_risk_score, desc unique_threat_count, desc _num_of_rows

// ===== TOP 25  =====
| limit 25
```
