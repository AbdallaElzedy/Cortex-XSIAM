```Coretex XSIAM XDR - Track USB\Bluetooth Activitiy 

dataset = xdr_data 
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS") //7 days

// Comprehensive device control event detection
| filter (
    // USB Device detection using actual USB fields
    action_device_usb_vendor_name != null or 
    action_device_usb_product_name != null or
    action_device_usb_vendor_id != null or
    
    // Bluetooth Registry Violations
    (event_type = 4 and event_sub_type = 4 and 
        action_registry_key_name contains "BTHLEDevice") or
    
    // Process events involving device drivers
    (event_type = 1 and action_process_image_name in (
        "pnputil.exe", "devcon.exe", "driverquery.exe"
    )) or
    
    // Registry events for device policies
    (event_type = 4 and action_registry_key_name contains "DeviceInstall")
)

// Device violation classification
| alter 
    violation_type = if(
        action_device_usb_vendor_name != null, "🔌 USB_DEVICE_CONNECTED",
        action_device_usb_vendor_id != null, "🔌 USB_DEVICE_DETECTED",
        action_registry_key_name contains "BTHLEDevice", "📱 BLUETOOTH_ACTIVITY",
        action_registry_key_name contains "DeviceInstall", "⚙️ DEVICE_POLICY_CHANGE",
        action_process_image_name in ("pnputil.exe", "devcon.exe"), "🔧 DEVICE_MANAGEMENT_TOOL",
        "🔍 OTHER_DEVICE_EVENT"
    ),
    
    risk_level = if(
        action_device_usb_vendor_name = null and action_device_usb_product_name = null and action_device_usb_vendor_id != null, "🔴 UNKNOWN_USB_DEVICE",
        actor_effective_username != "NT AUTHORITY\\SYSTEM" and action_registry_key_name contains "BTHLEDevice", "🟠 USER_BLUETOOTH_MODIFICATION",
        extract_time(_time, "HOUR") >= 18 or extract_time(_time, "HOUR") <= 6, "🟡 AFTER_HOURS_DEVICE_ACTIVITY",
        "✅ STANDARD_DEVICE_ACTIVITY"
    ),
    
    device_identifier = if(
        action_device_usb_serial_number != null, action_device_usb_serial_number,
        action_device_usb_vendor_name != null, concat(action_device_usb_vendor_name, " - ", action_device_usb_product_name),
        action_registry_key_name contains "BTHLEDevice", "BLUETOOTH_DEVICE",
        "UNKNOWN_DEVICE"
    ),
    
    user_context = coalesce(actor_effective_username, "SYSTEM"),
    timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time)

// Aggregate violations by type and risk
| comp 
    count() as violation_events,
    count_distinct(agent_hostname) as affected_hosts,
    count_distinct(device_identifier) as unique_devices,
    count_distinct(user_context) as users_involved,
    earliest(_time) as first_violation,
    latest(_time) as last_violation,
    values(agent_hostname) as hostnames,
    values(device_identifier) as device_list,
    values(user_context) as user_accounts
    by violation_type, risk_level

| alter 
    violation_timeframe = concat(
        format_timestamp("%Y-%m-%d %H:%M", first_violation),
        " → ",
        format_timestamp("%Y-%m-%d %H:%M", last_violation)
    ),
    
    violation_summary = concat(
        to_string(violation_events), " events | ",
        to_string(affected_hosts), " hosts | ",
        to_string(unique_devices), " devices | ",
        to_string(users_involved), " users"
    )

| fields 
    violation_type,
    risk_level,
    violation_timeframe,
    violation_summary,
    violation_events,
    affected_hosts,
    unique_devices,
    hostnames,
    device_list,
    user_accounts

| sort desc violation_events


```
