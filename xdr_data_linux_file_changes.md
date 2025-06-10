```Cortex XSIAM xdr_data_linux_file_changes
dataset = xdr_data
| filter agent_os_type = 2  // Linux 
// file event filtering
| filter (
    event_type = FILE and 
    event_sub_type in (FILE_CREATE_NEW, FILE_WRITE, FILE_REMOVE, FILE_RENAME)
)
// Linux file paths monitoring
| filter (
    // Critical system files
    action_file_path in (
        "/etc/shadow", "/etc/passwd", "/etc/group", "/etc/sudoers",
        "/etc/hosts", "/etc/fstab", "/etc/crontab", "/etc/ssh/sshd_config"
    ) or
    
    // Configuration directories
    action_file_path contains "/etc/" and 
    action_file_extension in ("conf", "cfg", "config", "txt", "") or
    
    // SSH configuration
    action_file_path contains  "/etc/ssh/" or
    action_file_path contains "/home/" and action_file_path contains ".ssh/" or
    
    // System binaries
    action_file_path contains  "/usr/bin/" or
    action_file_path contains "/usr/sbin/" or
    action_file_path contains "/bin/" or
    action_file_path contains "/sbin/" or
    
    // Init and service files
    action_file_path contains "/etc/init.d/" or
    action_file_path contains "/etc/systemd/" or
    action_file_path contains "/lib/systemd/"
)

// ===== FILE CHANGE ANALYSIS =====
| alter 
    // File change classification
    change_type = if(
        event_sub_type = FILE_CREATE_NEW, "📄 FILE_CREATED",
        event_sub_type = FILE_WRITE, "✏️ FILE_MODIFIED", 
        event_sub_type = FILE_REMOVE, "🗑️ FILE_DELETED",
        event_sub_type = FILE_RENAME, "📝 FILE_RENAMED",
        "🔍 OTHER_CHANGE"
    ),
    
    // file classification
   file_criticality = if(
    action_file_path in ("/etc/shadow", "/etc/passwd", "/etc/group"), "🔴 CRITICAL_USER_FILE",
    action_file_path = "/etc/sudoers", "🔴 CRITICAL_SUDO_CONFIG", 
    action_file_path contains "/ssh/", "🟠 SSH_CONFIGURATION",
    action_file_path contains "/etc/systemd/", "🟡 SERVICE_CONFIGURATION",
    (action_file_path contains "/usr/sbin/" or action_file_path contains "/sbin/"), "⚠️ SYSTEM_BINARY",
    "🟢 STANDARD_CONFIG_FILE"
),
    
    // Process information (what made the change)
// Process information (what made the change)
modifying_process = if(actor_process_image_name != null, actor_process_image_name, "UNKNOWN_PROCESS"),
process_path = if(actor_process_image_path != null, actor_process_image_path, "UNKNOWN_PATH"),
process_cmdline = if(actor_process_command_line != null, actor_process_command_line, "NO_CMDLINE"),

// User context
user_account = if(actor_effective_username != null, actor_effective_username, "SYSTEM"),

// File metadata
file_size_bytes = if(action_file_size != null, action_file_size, 0),
file_permissions = action_file_mode,

// Before/After content handling
file_content_before = if(action_file_previous_file_path != null, action_file_previous_file_path, "NO_PREVIOUS_CONTENT"),
file_content_sample =     if(action_file_contents != null, action_file_contents, "NO_CONTENT_CAPTURED"
),

// File hash information for integrity
file_hash_md5 = if(action_file_md5 != null, action_file_md5, "NO_MD5"),
file_hash_sha256 = if(action_file_sha256 != null, action_file_sha256, "NO_SHA256")

// ===== DETECT SUSPICIOUS PATTERNS =====
| alter 
    suspicious_indicator = if(
        // After hours modifications
        extract_time(_time, "HOUR") >= 22 or extract_time(_time, "HOUR") <= 6, "🌙 AFTER_HOURS_CHANGE",
        
        // Unusual processes modifying critical files
        file_criticality = "🔴 CRITICAL_USER_FILE" and 
        not modifying_process in ("usermod", "useradd", "userdel", "passwd", "chpasswd", "vipw"), "⚠️ UNUSUAL_PROCESS_MODIFYING_CRITICAL_FILE",
        
        // SSH config changes
        action_file_path contains "ssh" and 
        not modifying_process in ("sshd", "ssh-keygen", "authorized_keys"), "🔑 SSH_CONFIG_MODIFIED",
        
        // Binary modifications
        file_criticality = "⚠️ SYSTEM_BINARY", "🔧 SYSTEM_BINARY_CHANGE",
        
        // Sudo config changes
        action_file_path = "/etc/sudoers" and modifying_process != "visudo", "🚨 SUDOERS_MODIFIED_WITHOUT_VISUDO",
        
        "✅ NORMAL_CHANGE"
    )

// ===== OUTPUT =====
| fields 
    // Timing and basic info
    agent_hostname,
    agent_ip_addresses,
    
    // File information
    action_file_path,
    action_file_name,
    change_type,
    file_criticality,
    suspicious_indicator,
    
    // Process information (who made the change)
    modifying_process,
    process_path,
    process_cmdline,
    user_account,
    
    // File content and integrity
    file_content_sample,
    file_content_before,
    file_hash_md5,
    file_hash_sha256,
    
    // File metadata
    file_size_bytes,
    file_permissions,
    
    // Additional context
    actor_process_instance_id,
    action_file_type

| sort desc _time
```
