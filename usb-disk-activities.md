```
dataset = xdr_data
| filter event_type in (ENUM.DEVICE, ENUM.MOUNT , ENUM.FILE )
| filter action_device_usb_vendor_id != null
| sort asc _time
| windowcomp first_value(event_timestamp) by agent_hostname, action_device_usb_serial_number sort asc _time as plug_time
| windowcomp last_value(event_timestamp) by agent_hostname, action_device_usb_serial_number sort desc _time as unplug_time
| dedup agent_hostname, action_device_usb_vendor_id
| alter plug_ts = to_timestamp(plug_time, "MILLIS"),
unplug_ts = to_timestamp(unplug_time, "MILLIS") 
| alter
 plug_time_readable = format_timestamp("%Y-%m-%d %H:%M:%S", plug_ts, "America/New_York"),
unplug_time_readable = format_timestamp("%Y-%m-%d %H:%M:%S", unplug_ts, "America/New_York")
| alter session_duration_minutes = timestamp_diff(unplug_ts, plug_ts, "MINUTE")
| join type = right   (
    dataset = xdr_data
    | filter event_type = ENUM.FILE
    | filter action_device_usb_vendor_id != null
    | filter actor_effective_username not in ("NT AUTHORITY\SYSTEM")
           | filter actor_effective_username not contains  "\root"
    | alter  op =    if(event_sub_type = 1, "New file creation",
   event_sub_type = 2, "File access/opening",
   event_sub_type = 3, "File renaming",
   event_sub_type = 4, "File linking",
   event_sub_type = 5, "File deletion",
   event_sub_type = 6, "File modification",
   event_sub_type = 7, "File attribute changes",
   event_sub_type = 8, "Directory creation",
   event_sub_type = 9, "Directory access",
   event_sub_type = 10, "Directory renaming",
   event_sub_type = 11, "Directory linking",
   event_sub_type = 12, "Directory deletion",
   event_sub_type = 13, "File reparse operations",
   event_sub_type = 14, "File security changes",
   event_sub_type = 15, "File permission changes",
   event_sub_type = 16, "File ownership changes",
   to_string(event_sub_type))
| alter sanitized_path = replex(action_file_path, "[^a-zA-Z0-9_./\\-]", "")
    | alter file_op = to_string(concat(op, " : ", sanitized_path))
    | comp 
        count() as file_event_count, 
        values(file_op) as file_operations,
        values(actor_effective_username) as usernames
      by agent_hostname, action_device_usb_serial_number 
      | alter file_operations_top_100 = arrayrange(file_operations, 0, 100)
| fields file_event_count , file_operations_top_100, usernames , agent_hostname , action_device_usb_serial_number  
) as file_activity
file_activity.agent_hostname = agent_hostname and 
file_activity.action_device_usb_serial_number = action_device_usb_serial_number
| alter vendor_product = concat(  action_device_usb_vendor_name  , "   ", replace(action_device_usb_product_name,"unknown"," "))
| fields agent_os_type, agent_hostname, usernames, vendor_product,
         plug_time_readable, unplug_time_readable, session_duration_minutes,
         file_event_count, file_operations_top_100
| sort asc plug_time_readable
```
