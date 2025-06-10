```Cortex XSIAM ForcePoint Firewall -  NAT IP IDENTIFICATION & VALIDATION
dataset = forcepoint_firewall_raw 
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS")

    
| filter src = "<src_v>" and sourceTranslatedAddress != null

// JOIN: Cross-correlate with confirmed communication attempts
| join type = inner
    (dataset = forcepoint_firewall_raw 
     | filter _time > to_timestamp(subtract(to_epoch(current_time()), 604800), "SECONDS") //7 days
     | filter dst = "<dst_o>"
     | fields src as confirmed_nat_ip, 
              dst as confirmed_target,
              act as connection_result,
              app as connection_type,
              _time as attempt_time
    ) 
    as threat_correlation 
    sourceTranslatedAddress = threat_correlation.confirmed_nat_ip

// Establish NAT IP authority and confidence level
| comp 
    count() as correlation_events,
    count_distinct(sourceTranslatedAddress) as unique_nat_ips,
    earliest(_time) as first_correlation,
    latest(_time) as last_correlation,
    values(sourceTranslatedAddress) as validated_nat_ips,
    sum(if(connection_result = "Refuse", 1, 0)) as blocked_attempts,
    sum(if(connection_result = "Allow", 1, 0)) as successful_attempts
    by sourceTranslatedAddress

| alter 
    confidence_level = if(
        correlation_events > 100, "🔴 HIGH_CONFIDENCE",
        correlation_events > 50, "🟠 MEDIUM_CONFIDENCE", 
        correlation_events > 10, "🟡 LOW_CONFIDENCE",
        "⚪ INSUFFICIENT_DATA"
    ),

    investigation_timeframe = concat(
        format_timestamp("%Y-%m-%d %H:%M", first_correlation),
        " → ",
        format_timestamp("%Y-%m-%d %H:%M", last_correlation)
    )

| fields 
    sourceTranslatedAddress as authoritative_nat_ip,
    confidence_level,
    investigation_timeframe,
    correlation_events,
    blocked_attempts,
    successful_attempts
| limit 1

```
