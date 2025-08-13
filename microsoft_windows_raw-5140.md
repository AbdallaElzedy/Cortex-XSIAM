``` microsoft_windows_raw 5140 Object Operations  
config timeframe between "14d" and "now"
| dataset = microsoft_windows_raw 
| filter event_id = 5140
// | filter event_data contains " "
| alter 
    subject_username = json_extract_scalar(to_json_string(event_data), "$.SubjectUserName"),
    subject_domain = json_extract_scalar(to_json_string(event_data), "$.SubjectDomainName"),
    subject_user_sid = json_extract_scalar(to_json_string(event_data), "$.SubjectUserSid"),
    subject_logon_id = json_extract_scalar(to_json_string(event_data), "$.SubjectLogonId"),
    object_type = json_extract_scalar(to_json_string(event_data), "$.ObjectType"),
    source_ip = json_extract_scalar(to_json_string(event_data), "$.IpAddress"),
    source_port = json_extract_scalar(to_json_string(event_data), "$.IpPort"),
    share_name = json_extract_scalar(to_json_string(event_data), "$.ShareName"),
    share_path = json_extract_scalar(to_json_string(event_data), "$.ShareLocalPath"),
    access_mask = json_extract_scalar(to_json_string(event_data), "$.AccessMask"),
    access_list = json_extract_scalar(to_json_string(event_data), "$.AccessList"),
    target_server = host_name,
    os_version = os_subtype,
    process_info = process_name
| alter 
    user_domain = concat(subject_domain, "\\", subject_username),
    access_type = if(access_mask = "0x1", "Read_Control",
                     access_mask = "0x2", "Write_DAC", 
                     access_mask = "0x20", "Read_Data",
                     access_mask = "0x40", "Write_Data",
                     access_mask = "0x80", "Append_Data",
                     access_mask = "0x100", "Read_EA",
                     access_mask = "0x200", "Write_EA",
                     access_mask = "0x20000", "Delete",
                     access_mask = "0x40000", "Read_Control_2",
                     access_mask = "0x80000", "Write_DAC_2",
                     access_mask = "0x100000", "Write_Owner",
                     access_mask = "0x1000000", "Synchronize",
                     concat("Other_", access_mask)),
    share_type = if(share_name contains "IPC$", "IPC_Share",
                    share_name contains "ADMIN$", "Admin_Share",
                    share_name contains "C$", "Drive_Share",
                    share_name contains "PRINT$", "Print_Share",
                    share_name contains "NETLOGON", "Netlogon_Share",
                    share_name contains "SYSVOL", "Sysvol_Share",
                    "Custom_Share"),
    is_admin_share = if(share_name contains "$", true, false),
    source_ip_type = if(incidr(source_ip, "10.0.0.0/8") or incidr(source_ip, "172.16.0.0/12") or incidr(source_ip, "192.168.0.0/16"), "Internal", "External"),
    formatted_time = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
    hour_of_day = extract_time(_time, "HOUR"),
    day_of_week = extract_time(_time, "DAYOFWEEK")
| comp 
    count() as total_accesses,
    count_distinct(subject_username) as unique_users,
    count_distinct(source_ip) as unique_source_ips,
    count_distinct(target_server) as unique_target_servers,
    count_distinct(share_name) as unique_shares,
    count_distinct(source_port) as unique_source_ports,
    values(user_domain) as users,
    values(source_ip) as source_addresses,
    values(target_server) as target_servers,
    values(share_name) as share_names,
    values(share_path) as share_paths,
    values(access_mask) as access_masks,
    values(access_list) as access_lists,
    values(source_port) as source_ports,
    values(os_version) as operating_systems,
    values(hour_of_day) as active_hours,
    min(formatted_time) as first_access,
    max(formatted_time) as last_access,
    list(formatted_time) as sample_times,
    list(source_ip) as sample_source_ips
by share_type, access_type, is_admin_share, source_ip_type
| alter 
    sample_times_limited = arrayrange(sample_times, 0, 5),
    sample_ips_limited = arrayrange(sample_source_ips, 0, 5)
| fields 
    users,
    source_addresses,
    target_servers,
    share_names,
    share_paths,
    total_accesses,
    share_type,
    access_type,
    is_admin_share,
    source_ip_type,
    unique_users,
    unique_source_ips,
    unique_target_servers,
    unique_shares,
    unique_source_ports,
    access_masks,
    access_lists,
    active_hours,
    first_access,
    last_access,
    sample_times_limited,
    sample_ips_limited,
    operating_systems
| sort desc total_accesses

```
