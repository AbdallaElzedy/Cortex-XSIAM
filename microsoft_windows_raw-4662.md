``` microsoft_windows_raw 4662 object operations 
config timeframe between "14d" and "now"
| dataset = microsoft_windows_raw 
//| filter event_data contains " " // <--// Username 
| filter event_id = 4662 
| alter 
    subject_username = json_extract_scalar(to_json_string(event_data), "$.SubjectUserName"),
    subject_domain = json_extract_scalar(to_json_string(event_data), "$.SubjectDomainName"),
    subject_user_sid = json_extract_scalar(to_json_string(event_data), "$.SubjectUserSid"),
    subject_logon_id = json_extract_scalar(to_json_string(event_data), "$.SubjectLogonId"),
    properties_raw = json_extract_scalar(to_json_string(event_data), "$.Properties"),
    object_type = json_extract_scalar(to_json_string(event_data), "$.ObjectType"),
    object_name = json_extract_scalar(to_json_string(event_data), "$.ObjectName"),
    object_server = json_extract_scalar(to_json_string(event_data), "$.ObjectServer"),
    access_mask = json_extract_scalar(to_json_string(event_data), "$.AccessMask"),
    operation_type = json_extract_scalar(to_json_string(event_data), "$.OperationType"),
    handle_id = json_extract_scalar(to_json_string(event_data), "$.HandleId"),
    access_list = json_extract_scalar(to_json_string(event_data), "$.AccessList"),
    additional_info = json_extract_scalar(to_json_string(event_data), "$.AdditionalInfo")
| alter 
    user_domain = concat(subject_domain, "\\", subject_username),
    // Enhanced GUID categorization
    guid_category = if(properties_raw contains "bf967a86-0de6-11d0-a285-00aa003049e2", "User_Class",
                    if(properties_raw contains "bf967aba-0de6-11d0-a285-00aa003049e2", "Group_Class",
                    if(properties_raw contains "f30e3bbe-9ff0-11d1-b603-0000f80367c1", "Group_Policy",
                    if(properties_raw contains "19195a5b-6da0-11d0-afd3-00c04fd930c9", "Domain_Class", "Other")))),
    // Enhanced access mask interpretation
    access_type = if(access_mask = "0x100", "Control_Access",
                  if(access_mask = "0x20", "Read_Property", 
                  if(access_mask = "0x10", "Write_Property",
                  if(access_mask = "0x1", "Read_Control",
                  if(access_mask = "0x20000", "Generic_Read",
                  if(access_mask = "0x8", "Read_Security",
                  if(access_mask = "0x0", "No_Access", 
                  concat("Unknown_", access_mask)))))))),
    // Extract object GUID
    object_guid = arrayindex(regextract(object_name, "%\{([a-f0-9\-]+)\}"), 0),
    // Properties analysis
    property_guid_list = arraystring(regextract(properties_raw, "\{([a-f0-9\-]+)\}"), ", "),
    guid_count = array_length(regextract(properties_raw, "\{([a-f0-9\-]+)\}")),
    // Time analysis
    formatted_time = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
    hour_of_day = extract_time(_time, "HOUR"),
    day_of_week = extract_time(_time, "DAYOFWEEK"),
    date_only = format_timestamp("%Y-%m-%d", _time)
| filter properties_raw contains "bf967a86-0de6-11d0-a285-00aa003049e2" or
        properties_raw contains "bf967aba-0de6-11d0-a285-00aa003049e2" or
        properties_raw contains "f30e3bbe-9ff0-11d1-b603-0000f80367c1" or
        properties_raw contains "19195a5b-6da0-11d0-afd3-00c04fd930c9"
| comp 
    count() as event_count,
    // User and Authentication Details
    values(user_domain) as users,
    values(subject_user_sid) as user_sids,
    values(subject_logon_id) as logon_sessions,
    // Server and Infrastructure 
    values(computer_name) as domain_controllers,
    values(object_server) as object_servers,
    values(provider_name) as event_providers,
    // Object Access Details
    count_distinct(object_name) as unique_objects,
    count_distinct(object_guid) as unique_object_guids,
    values(object_type) as object_class_types,
    values(operation_type) as operation_types,
    values(handle_id) as handle_ids,
    // Access Control Details
    values(access_mask) as access_masks,
    values(access_list) as access_lists,
    values(additional_info) as additional_details,
    // Properties Analysis
    min(guid_count) as min_properties,
    max(guid_count) as max_properties,
    avg(guid_count) as avg_properties,
    // Time Analysis
    values(hour_of_day) as active_hours,
    values(day_of_week) as active_days,
    count_distinct(date_only) as days_active,
    min(formatted_time) as first_occurrence,
    max(formatted_time) as last_occurrence,
    // Sample Data for Investigation
    list(object_guid) as sample_object_guids,
    list(property_guid_list) as sample_property_lists,
    list(object_name) as sample_object_names,
    list(formatted_time) as sample_times
by guid_category, access_type, event_result
| alter 
    failure_indicator = if(event_result = "failure", "❌ DENIED", "✅ ALLOWED"),
    // Time-based analysis
    activity_duration_days = if(days_active > 1, timestamp_diff(parse_timestamp("%Y-%m-%d %H:%M:%S", last_occurrence), parse_timestamp("%Y-%m-%d %H:%M:%S", first_occurrence), "DAY"), 0),
    avg_events_per_day = if(days_active > 0, divide(event_count, days_active), event_count),
    time_pattern = if(array_length(active_hours) > 12, "All_Day_Activity", "Time_Specific_Activity"),
    // Limit samples for readability
    sample_objects_limited = arrayrange(sample_object_names, 0, 3),
    sample_guids_limited = arrayrange(sample_object_guids, 0, 5),
    sample_properties_limited = arrayrange(sample_property_lists, 0, 2),
    sample_times_limited = arrayrange(sample_times, 0, 5)
| fields 
    domain_controllers,
    logon_sessions,
    event_count,
    guid_category, 
    access_type, 
    failure_indicator,
    // User Context
    users,
    user_sids,
    object_servers,
    // Object Details
    unique_objects,
    unique_object_guids,
    object_class_types,
    operation_types,
    // Access Control
    access_masks,
    access_lists,
    handle_ids,
    // Properties
    min_properties,
    max_properties,
    avg_properties,
    // Time Analysis
    days_active,
    activity_duration_days,
    avg_events_per_day,
    time_pattern,
    active_hours,
    active_days,
    first_occurrence,
    last_occurrence,
    // Samples 
    sample_objects_limited,
    sample_guids_limited,
    sample_properties_limited,
    sample_times_limited,
    additional_details
| sort desc event_count
