```Cortex XSIAM Investigate Traffic behind NAT
dataset = forcepoint_firewall_raw 
//| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
| filter src = "<src_v>" and sourceTranslatedAddress != null
| fields _time, src, dst, sourceTranslatedAddress, act, app, dpt, proto

// JOIN: Find which NAT IPs are trying to reach the destination
| join type = inner
    (dataset = forcepoint_firewall_raw 
     | filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")
     | filter dst = "<dst_o>"
     | fields src as nat_ip, dst as target_ip, act as target_action, app as target_app
    ) 
    as offender_attempts 
    sourceTranslatedAddress = offender_attempts.nat_ip

// ===== ANALYZE THE CONNECTION PATH =====
| alter 
    connection_flow = concat("<src_v> → NAT(", sourceTranslatedAddress, ") → <dst_o>"),
    victim_result = act,
    offender_result = target_action,
    timestamp = format_timestamp("%Y-%m-%d %H:%M:%S", _time)

| fields 
    timestamp,
    connection_flow,
    dst as victim_destination,
    victim_result,
    offender_result,
    target_app,
    dpt,
    sourceTranslatedAddress

| sort asc _time
| limit 20

```
