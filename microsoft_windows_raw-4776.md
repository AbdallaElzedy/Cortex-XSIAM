```  microsoft_windows_raw 4776  credentials validatition - computer
dataset = microsoft_windows_raw 
| filter event_id = 4776
//| filter event_data contains " "
| alter 
    target_username = json_extract_scalar(to_json_string(event_data), "$.TargetUserName"),
    package_name = json_extract_scalar(to_json_string(event_data), "$.PackageName"),
    status_code = json_extract_scalar(to_json_string(event_data), "$.Status"),
    logon_account = arrayindex(regextract(message, "Logon Account:\s+([^\n\r]+)"), 0),
    source_workstation = arrayindex(regextract(message, "Source Workstation:\s+([^\n\r]+)"), 0),
    error_code = arrayindex(regextract(message, "Error Code:\s+([^\n\r]+)"), 0),
    auth_package = arrayindex(regextract(message, "Authentication Package:\s+([^\n\r]+)"), 0),
    validating_dc = computer_name,
    collector_info = _collector_name
| alter 
    auth_result = if(status_code = "0x0", "✅ SUCCESS", 
                     status_code = "0xc000006a", "❌ WRONG_PASSWORD",
                     status_code = "0xc0000064", "❌ USER_NOT_FOUND",
                     status_code = "0xc000006f", "❌ OUTSIDE_HOURS",
                     status_code = "0xc0000070", "❌ WORKSTATION_RESTRICTION",
                     status_code = "0xc0000071", "❌ PASSWORD_EXPIRED",
                     status_code = "0xc0000072", "❌ ACCOUNT_DISABLED",
                     status_code = "0xc000006d", "❌ WRONG_USERNAME",
                     status_code = "0xc000006e", "❌ ACCOUNT_RESTRICTION",
                     status_code = "0xc0000234", "❌ ACCOUNT_LOCKED",
                     concat("❌ ERROR_", status_code)),
    auth_type = if(package_name contains "NTLM", "NTLM",
                   package_name contains "KERBEROS", "Kerberos",
                   package_name contains "MICROSOFT_AUTHENTICATION", "NTLM_V1", 
                   "Other"),
    has_source_workstation = if(source_workstation != null and source_workstation != "" and source_workstation != "-", true, false),
    workstation_clean = if(source_workstation = "" or source_workstation = "-", "Unknown/Local", source_workstation),
    is_failure = if(event_result = "failure" or status_code != "0x0", true, false),
    formatted_time = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
    hour_of_day = extract_time(_time, "HOUR"),
    day_of_week = extract_time(_time, "DAYOFWEEK")
| comp 
    count() as total_attempts,
    count_distinct(target_username) as unique_users,
    count_distinct(validating_dc) as unique_dcs,
    count_distinct(workstation_clean) as unique_workstations,
    count_distinct(status_code) as unique_status_codes,
    sum(if(is_failure = false, 1, 0)) as successful_auths,
    sum(if(is_failure = true, 1, 0)) as failed_auths,
    values(target_username) as usernames,
    values(validating_dc) as domain_controllers,
    values(workstation_clean) as source_workstations,
    values(status_code) as status_codes,
    values(error_code) as error_codes,
    values(auth_package) as auth_packages,
    values(package_name) as package_names,
    values(hour_of_day) as active_hours,
    min(formatted_time) as first_attempt,
    max(formatted_time) as last_attempt,
    list(formatted_time) as sample_times,
    list(workstation_clean) as sample_workstations_detail
by auth_result, auth_type, has_source_workstation
| alter 
    failure_rate = if(total_attempts > 0, divide(multiply(failed_auths, 100), total_attempts), 0),
    success_rate = if(total_attempts > 0, divide(multiply(successful_auths, 100), total_attempts), 0),
    sample_times_limited = arrayrange(sample_times, 0, 5),
    sample_workstations_limited = arrayrange(sample_workstations_detail, 0, 5)
| fields 
    usernames,
    domain_controllers,
    source_workstations,
    unique_workstations,
    total_attempts,
    auth_result,
    auth_type,
    has_source_workstation,
    successful_auths,
    failed_auths,
    success_rate,
    failure_rate,
    unique_users,
    unique_dcs,
    unique_status_codes,
    status_codes,
    error_codes,
    auth_packages,
    active_hours,
    first_attempt,
    last_attempt,
    sample_times_limited,
    sample_workstations_limited
| sort desc total_attempts
```
