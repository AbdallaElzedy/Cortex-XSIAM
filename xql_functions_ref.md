# XQL (Cortex Query Language) Guide: The Complete Functions Reference

## Table of Contents

1. [Introduction](#introduction)
2. [Basic XQL Query Structure](#basic-xql-query-structure)
3. [Core Functions Reference](#core-functions-reference)
   - [Mathematical Functions](#mathematical-functions)
   - [String Manipulation Functions](#string-manipulation-functions)
   - [Array Functions](#array-functions)
   - [Time and Date Functions](#time-and-date-functions)
   - [JSON Functions](#json-functions)
   - [IP Address Functions](#ip-address-functions)
   - [Aggregation Functions](#aggregation-functions)
   - [Window Functions](#window-functions)
4. [Common XQL Patterns](#common-xql-patterns)
5. [Best Practices](#best-practices)
6. [Examples](#examples)

## Introduction

XQL (Cortex Query Language) is a powerful query language used in Palo Alto Networks' Cortex XDR platform. It allows you to search, filter, transform, and analyze data efficiently. This guide serves as a comprehensive reference for XQL functions and usage patterns.

## Basic XQL Query Structure

An XQL query typically follows this pipeline structure:

```
dataset = <dataset_name>
| <operation_1>
| <operation_2>
| ...
| <operation_n>
```

Common operations include:

- `fields` - Select specific fields to include in results
- `filter` - Filter records based on conditions
- `alter` - Create or modify fields
- `limit` - Restrict the number of returned results
- `sort` - Order results by specified fields
- `dedup` - Remove duplicate records
- `comp` - Perform computations and aggregations
- `windowcomp` - Perform window-based computations
- `bin` - Group data into time-based bins

## XQL Functions Reference

### Mathematical Functions

| Function | Description | Example |
|----------|-------------|---------|
| `add()` | Adds two positive integers | `add(action_file_size, 3)` |
| `subtract()` | Subtracts the second value from the first | `subtract(action_file_size, 3)` |
| `multiply()` | Multiplies two positive integers | `multiply(action_file_size, 3)` |
| `divide()` | Divides the first value by the second | `divide(action_file_size, 3)` |
| `pow()` | Raises a number to the power of another | `pow(value, 2)` |
| `round()` | Rounds a number to the nearest integer | `round(value)` |
| `floor()` | Rounds a number down to the nearest integer | `floor(value)` |

### String Manipulation Functions

| Function | Description | Example |
|----------|-------------|---------|
| `concat()` | Joins multiple strings | `concat("str: ", to_string(value))` |
| `len()` | Returns the length of a string | `len(dns_query_name)` |
| `lowercase()` | Converts string to lowercase | `lowercase(field_name)` |
| `uppercase()` | Converts string to uppercase | `uppercase(field_name)` |
| `replace()` | Replaces occurrences of a substring | `replace(field, ".exe", "")` |
| `replex()` | Replaces matches of a regex pattern | `replex(field, pattern, replacement)` |
| `split()` | Splits a string by delimiter | `split(ip_address, ".")` |
| `trim()`, `ltrim()`, `rtrim()` | Removes characters from string | `rtrim(field, ".exe")` |
| `regextract()` | Extracts substrings matching a pattern | `regextract(field, pattern)` |
| `string_count()` | Counts occurrences of a substring | `string_count(field, "e")` |
| `format_string()` | Formats a string using specifiers | `format_string("-%s-", field)` |

### Array Functions

| Function | Description | Example |
|----------|-------------|---------|
| `arraycreate()` | Creates an array | `arraycreate("1", "2")` |
| `arrayconcat()` | Concatenates arrays | `arrayconcat(array1, array2)` |
| `arraydistinct()` | Returns array with unique elements | `arraydistinct(array)` |
| `arrayfilter()` | Filters array elements by condition | `arrayfilter(array, "@element" = "value")` |
| `arrayindex()` | Returns element at specified index | `arrayindex(array, 2)` |
| `arrayindexof()` | Returns index of element | `arrayindexof(array, "@element" = "value")` |
| `array_length()` | Returns array length | `array_length(array)` |
| `arraymap()` | Applies function to all elements | `arraymap(array, function)` |
| `arraymerge()` | Merges JSON string arrays | `arraymerge(array)` |
| `arrayrange()` | Returns a slice of an array | `arrayrange(array, 2, 4)` |
| `arraystring()` | Joins array elements into string | `arraystring(array, ",")` |
| `array_all()` | Returns true when all elements match | `array_all(array, "@element" = "value")` |
| `array_any()` | Returns true when any element matches | `array_any(array, "@element" = "value")` |

### Time and Date Functions

| Function | Description | Example |
|----------|-------------|---------|
| `current_time()` | Returns current timestamp | `current_time()` |
| `date_floor()` | Rounds timestamp down to unit | `date_floor(timestamp, "d")` |
| `extract_time()` | Returns part of a timestamp | `extract_time(timestamp, "HOUR")` |
| `format_timestamp()` | Formats timestamp as string | `format_timestamp("%Y/%m/%d", timestamp)` |
| `parse_timestamp()` | Parses string to timestamp | `parse_timestamp("%m/%d/%Y", date_string)` |
| `parse_epoch()` | Converts string to epoch timestamp | `parse_epoch("%c", date_string)` |
| `timestamp_diff()` | Calculates difference between timestamps | `timestamp_diff(ts1, ts2, "MINUTE")` |
| `timestamp_seconds()` | Converts epoch seconds to timestamp | `timestamp_seconds(epoch_value)` |
| `to_epoch()` | Converts timestamp to epoch | `to_epoch(timestamp, "MILLIS")` |
| `to_timestamp()` | Converts epoch to timestamp | `to_timestamp(epoch_value, "MILLIS")` |
| `time_frame_end()` | Returns end of query time frame | `time_frame_end()` |

### JSON Functions

| Function | Description | Example |
|----------|-------------|---------|
| `json_extract()` | Extracts JSON objects | `json_extract(json, "$.field")` |
| `json_extract_array()` | Extracts JSON array | `json_extract_array(json, "$.array")` |
| `json_extract_scalar()` | Extracts scalar values | `json_extract_scalar(json, "$.value")` |
| `json_extract_scalar_array()` | Extracts array of scalars | `json_extract_scalar_array(json, "$.array")` |
| `to_json_string()` | Converts to JSON string | `to_json_string(value)` |
| `object_create()` | Creates an object | `object_create("key", "value")` |
| `object_merge()` | Merges objects | `object_merge(obj1, obj2)` |

### IP Address Functions

| Function | Description | Example |
|----------|-------------|---------|
| `incidr()` | Checks if IP is in CIDR range | `incidr(ip, "192.168.0.0/24")` |
| `incidr6()` | Checks if IPv6 is in CIDR range | `incidr6(ipv6, "fe80::/10")` |
| `incidrlist()` | Checks if IP list is in CIDR range | `incidrlist("192.168.1.1,192.168.1.2", "192.168.0.0/16")` |
| `ip_to_int()` | Converts IPv4 to integer | `ip_to_int("192.168.1.1")` |
| `int_to_ip()` | Converts integer to IPv4 | `int_to_ip(3232235777)` |
| `extract_url_host()` | Extracts host from URL | `extract_url_host("https://www.example.com")` |
| `extract_url_pub_suffix()` | Extracts public suffix | `extract_url_pub_suffix("https://www.example.com")` |
| `extract_url_registered_domain()` | Extracts registered domain | `extract_url_registered_domain("https://www.example.com")` |

### Aggregation Functions

| Function | Description | Example with `comp` |
|----------|-------------|---------|
| `avg()` | Calculates average | `comp avg(field) by group_field` |
| `count()` | Counts rows | `comp count() by group_field` |
| `count_distinct()` | Counts unique values | `comp count_distinct(field) by group_field` |
| `max()` | Finds maximum value | `comp max(field) by group_field` |
| `min()` | Finds minimum value | `comp min(field) by group_field` |
| `sum()` | Calculates sum | `comp sum(field) by group_field` |
| `list()` | Returns array of values | `comp list(field) by group_field` |
| `values()` | Returns array of unique values | `comp values(field) by group_field` |
| `first()` | Returns first value | `comp first(field) by group_field` |
| `last()` | Returns last value | `comp last(field) by group_field` |
| `earliest()` | Returns chronologically earliest value | `comp earliest(field) by group_field` |
| `latest()` | Returns chronologically latest value | `comp latest(field) by group_field` |
| `median()` | Calculates median | `comp median(field) by group_field` |
| `stddev_population()` | Calculates population standard deviation | `comp stddev_population(field) by group_field` |
| `stddev_sample()` | Calculates sample standard deviation | `comp stddev_sample(field) by group_field` |
| `var()` | Calculates variance | `comp var(field) by group_field` |
| `approx_count()` | Approximates count of distinct values | `comp approx_count(field) by group_field` |
| `approx_quantiles()` | Approximates quantiles | `comp approx_quantiles(field, 100, true) by group_field` |
| `approx_top()` | Approximates top elements | `comp approx_top(field, 10) by group_field` |

### Window Functions

| Function | Description | Example with `windowcomp` |
|----------|-------------|---------|
| `row_number()` | Assigns sequential row numbers | `windowcomp row_number() by field sort field as row_num` |
| `rank()` | Assigns ranks | `windowcomp rank() by field sort field as rank_num` |
| `lag()` | Accesses previous row value | `windowcomp lag(field) by group sort time as prev_value` |
| `first_value()` | Gets first value in window | `windowcomp first_value(field) by group sort time as first_val` |
| `last_value()` | Gets last value in window | `windowcomp last_value(field) by group sort time as last_val` |

## Common XQL Patterns

### Filtering Data

```
dataset = xdr_data
| filter field_name = "value"
| filter numeric_field > 100
| filter string_field != null
| filter string_field contains "substring"
| filter ip_field ~= "^192\.168\."  # Regex match
```

### Creating New Fields

```
dataset = xdr_data
| alter new_field = "static value"
| alter calculated_field = field1 + field2
| alter transformed_field = if(condition, true_value, false_value)
```

### Working with Time

```
dataset = xdr_data
| filter timestamp_diff(current_time(), _time, "DAY") < 7
| alter day_of_week = extract_time(_time, "DAYOFWEEK")
| bin _time span = 1h
```

### Grouping and Aggregating

```
dataset = xdr_data
| comp count() by field1, field2
| comp values(field3) as unique_values by field1
```

### Advanced Windowing

```
dataset = xdr_data
| windowcomp avg(metric) by host sort asc time between -5 and 0 as rolling_avg
| filter metric > rolling_avg * 2  # Find outliers
```

## Best Practices

1. **Filter Early**: Apply filters as early as possible to reduce the data volume.
2. **Limit Fields**: Use the `fields` operator to select only necessary columns.
3. **Use Aliases**: Rename fields for clarity using `as` notation.
4. **Set Limits**: Always use `limit` for ad-hoc queries to prevent large result sets.
5. **Type Conversion**: Convert data types when needed using functions like `to_integer()` or `to_timestamp()`.
6. **Format Output**: Use functions like `format_string()` or `format_timestamp()` for readable output.
7. **Include Comments**: Document complex queries with comments for future reference.
8. **Test Incrementally**: Build complex queries step by step, testing each part.

## Examples

### Basic Data Exploration

```
dataset = xdr_data
| fields _time, actor_process_image_path, actor_process_command_line, action_file_path
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 86400), "SECONDS")
| limit 100
```

### Identifying Unusual Network Activity

```
dataset = xdr_data
| filter action_local_ip != null and action_remote_ip != null
| comp count() as connection_count by action_local_ip, action_remote_ip
| filter connection_count > 100
| sort desc connection_count
```

### Finding Processes with Multiple Command Lines

```
dataset = xdr_data
| fields actor_process_image_path, actor_process_command_line
| filter actor_process_image_path != null and actor_process_command_line != null
| comp count_distinct(actor_process_command_line) as cmd_count by actor_process_image_path
| filter cmd_count > 5
| sort desc cmd_count
```

### Time Series Analysis of System Events

```
dataset = xdr_data
| filter event_type = "PROCESS_EXECUTION"
| alter hour_of_day = extract_time(_time, "HOUR")
| comp count() as event_count by hour_of_day
| sort asc hour_of_day
```

### Extracting Information from JSON Fields

```
dataset = xdr_data
| filter action_file_device_info != null
| alter device_type = json_extract_scalar(to_json_string(action_file_device_info), "$.storage_device_drive_type")
| alter device_name = json_extract_scalar(to_json_string(action_file_device_info), "$.storage_device_name")
| comp count() by device_type, device_name
```

### IP Address Analysis

```
dataset = xdr_data
| filter action_local_ip != null
| alter is_internal = incidr(action_local_ip, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16")
| comp count() as ip_count by action_local_ip, is_internal
| sort desc ip_count
```

### Advanced Pattern Detection

```
dataset = xdr_data
| filter actor_process_image_path != null 
| windowcomp count() by agent_hostname sort asc _time between -5m and 0 as process_count
| filter process_count > 20
| comp values(actor_process_image_path) as processes by agent_hostname
```
