``` xdr_data_bluetooth_disc_timeline
// STORY: Device Discovery Timeline
dataset = xdr_data 
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
| filter action_registry_key_name contains "5c25fc7be2e5"
| alter 
    timeline_event = if(
        action_registry_value_name = "Bluetooth_UniqueID", "📱 DEVICE_PAIRED",
        action_registry_key_name contains "Properties" and action_registry_key_name contains "0067", "🔋 BATTERY_INFO_UPDATE",
        action_registry_key_name contains "Properties" and action_registry_key_name contains "000a", "⚙️ DEVICE_DESCRIPTOR_UPDATE",
        action_registry_key_name contains "Properties" and action_registry_key_name contains "0003", "📊 DEVICE_CLASS_UPDATE",
        action_registry_key_name contains "Properties", "⚙️ PROPERTY_UPDATE",
        "🔍 OTHER_EVENT"
    ),
    service_detected = if(
        action_registry_key_name contains "{d0611e78-bbb4-4591-a5f8-487910ae4366}", "🔹 CUSTOM_SERVICE",
        action_registry_key_name contains "{00001805-0000-1000-8000-00805f9b34fb}", "📊 CURRENT_TIME_SERVICE", 
        action_registry_key_name contains "{0000180f-0000-1000-8000-00805f9b34fb}", "🔋 BATTERY_SERVICE",
        "❓ UNKNOWN_SERVICE"
    ),
    timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time),
    hour = extract_time(_time, "HOUR")

| comp count() as events,
       values(action_registry_data) as data_samples,
       earliest(_time) as first_event,
       latest(_time) as last_event
       by timeline_event, service_detected, hour
| alter event_timeframe = concat(
    format_timestamp("%H:%M", first_event), " - ", format_timestamp("%H:%M", last_event)
)
| sort desc events
| limit 20
```
