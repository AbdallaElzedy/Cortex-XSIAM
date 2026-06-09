# Process Causality Chain for Suspicious Network Destination (Cortex XQL)

> Author: **Abdalla Elzedy**, Security Engineer

A Cortex XSIAM / XDR investigation query that reconstructs the **full process
causality chain** behind a host connecting to a suspicious external destination.
Starting from a network `STORY` event to a flagged hostname, it joins back to the
originating `PROCESS_START` to lay out the complete parent/child lineage, from the
causality root down to the process that made the connection.

> **Note:** The target hostname and the suspicious destination have been replaced
> with `<PLACEHOLDERS>`. See [Customization](#customization) before running this in
> your own tenant.

## What it does

1. Selects `STORY` (network) events on a specific host where the external
   destination matches a suspicious hostname.
2. Left-joins the matching `PROCESS_START` events (on the same host and
   `actor_process_instance_id`) to recover process command lines and PIDs.
3. Maps the XDR causality fields into a readable four-level lineage plus the
   network destination.
4. Builds a single `complete_chain` string summarizing the whole path:

```
1. Causality Root -> 2. OS Parent -> 3. Action Parent -> 4. Network Process -> 5. Destination
```

This is most useful as a hunt / triage query once you have an indicator (a domain,
CDN endpoint, or C2 hostname) and want to know exactly which process tree reached out
to it.

## Query

```xql
config case_sensitive = false
| dataset = xdr_data
| filter agent_hostname = "<TARGET_HOSTNAME>"
| filter event_type = ENUM.STORY
| filter dst_action_external_hostname contains "<SUSPICIOUS_HOSTNAME>"
| join type=left (
    dataset = xdr_data
    | filter agent_hostname = "<TARGET_HOSTNAME>"
    | filter event_type = ENUM.PROCESS
    | filter event_sub_type = ENUM.PROCESS_START
    | fields agent_hostname, actor_process_instance_id, os_actor_process_image_name, os_actor_process_os_pid, action_process_image_name, action_process_os_pid, action_process_image_command_line
) as PROC PROC.actor_process_instance_id = actor_process_instance_id and proc.agent_hostname = agent_hostname
| alter
    level_1_root_causality = causality_actor_process_image_name,
    level_1_pid = causality_actor_process_os_pid,
    level_2_os_parent = os_actor_process_image_name,
    level_2_pid = os_actor_process_os_pid,
    level_3_action_parent = action_process_image_name,
    level_3_pid = action_process_os_pid,
    level_3_cmdline = action_process_image_command_line,
    level_4_current_process = actor_process_image_name,
    level_4_pid = actor_process_os_pid,
    destination = dst_action_external_hostname,
    threat_category = dst_action_url_category,
    remote_ip = action_remote_ip
| alter
    complete_chain = concat(
        "1. Causality Root: ", level_1_root_causality, " (", to_string(level_1_pid), ") → ",
        "2. OS Parent: ", level_2_os_parent, " (", to_string(level_2_pid), ") → ",
        "3. Action Parent: ", level_3_action_parent, " (", to_string(level_3_pid), ") → ",
        "4. Network Process: ", level_4_current_process, " (", to_string(level_4_pid), ") → ",
        "5. Destination: ", destination, " [", threat_category, "]"
    )
| fields
    _time,
    complete_chain,
    level_1_root_causality,
    level_1_pid,
    level_2_os_parent,
    level_2_pid,
    level_3_action_parent,
    level_3_pid,
    level_3_cmdline,
    level_4_current_process,
    level_4_pid,
    destination,
    threat_category,
    remote_ip
```

## Customization

Replace these placeholders with values for your environment before running:

| Placeholder | Replace with | Used for |
|-------------|--------------|----------|
| `<TARGET_HOSTNAME>` | The endpoint you are investigating, e.g. `host-01` | Scoping both the network event and the process join to one host |
| `<SUSPICIOUS_HOSTNAME>` | The destination indicator you are hunting (domain, CDN endpoint, or C2 host) | Matching the suspicious outbound connection |

To run this broadly instead of for a single host, you can drop the
`agent_hostname` filters (and the matching join condition) and pivot on the
destination alone. Be aware this widens the result set and may need additional
filtering.

## Notes

- The query relies on XDR causality fields (`causality_actor_*`, `os_actor_*`,
  `action_process_*`, `actor_process_*`) to express the four-level lineage. If any
  level is blank in your results, that level was not populated for that event.
- The `join type=left` keeps network events even when no matching `PROCESS_START`
  is found, so you can still see connections whose process context is missing.
- `dst_action_url_category` is surfaced as `threat_category` for quick triage of how
  the destination is classified.

