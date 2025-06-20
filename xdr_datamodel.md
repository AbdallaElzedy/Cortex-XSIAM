# XDR Data Model Documentation
![XQL Banner](https://img.shields.io/badge/XQL-Reference%20Guide-blue)
![Cortex XSIAM](https://img.shields.io/badge/Cortex-XSIAM-red)
![Version](https://img.shields.io/badge/Version-1.0-green)
![Last Updated](https://img.shields.io/badge/Last%20Updated-June%202025-lightgrey)

**Author:** Abdalla Elzedy | Security Engineer

> **Disclaimer:** This is **not official documentation** from Palo Alto Networks. This guide represents a community initiative to bridge the documentation gap and empower security professionals. Created independently with love for the cybersecurity community, this resource aims to unlock the full potential of XDR data models and make advanced threat hunting accessible to all practitioners.

## Overview

This document describes the XDR data model that transforms raw security event data into a standardized format using XQL. The model handles two main data streams:

1. **Network/Authentication Stories** - VPN events, network connections, authentication events
2. **Endpoint Events** - Process, file, registry, and module loading activities

## XQL and ENUM Constants

This data model is designed for use with **Cortex XDR/XSIAM** using **XQL**. XQL uses ENUM constants to provide standardized, normalized access to security data regardless of the original log source.

### Understanding ENUM Constants

When you write XQL queries like:
```sql
filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
and event_type = ENUM.PROCESS 
and event_sub_type in (ENUM.PROCESS_START, ENUM.PROCESS_STOP)
```

These ENUM constants are **normalized identifiers** that map to underlying values, ensuring consistent querying across different data sources.

## Table of Contents

- [Filtering Conditions](#filtering-conditions)
- [Event Types & Sub-Types](#event-types--sub-types)
- [Operating System Support](#operating-system-support)
- [Story Type Classifications](#story-type-classifications)
- [Field Mappings](#field-mappings)
- [Network Protocol Support](#network-protocol-support)
- [Authentication Methods](#authentication-methods)
- [File Operations](#file-operations)
- [Registry Operations](#registry-operations)

## Filtering Conditions

### Primary Event Filters

The model processes events based on these primary filters:

#### Network/Authentication Stories
```sql
event_type in (ENUM.STORY, ENUM.VPN_EVENT)
```

#### Endpoint Events
**Filter**: `event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY, ENUM.LOAD_IMAGE)`
```sql
event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY, ENUM.LOAD_IMAGE)
```

## Event Types & Sub-Types

### Understanding Event Type ENUMs

Each event type in XDR is assigned a unique ENUM constant with an underlying numeric value:

| ENUM Constant | Numeric Value | Description |
|---------------|---------------|-------------|
| `ENUM.PROCESS` | 1 | Process events |
| `ENUM.NETWORK` | 2 | Network events |
| `ENUM.FILE` | 3 | File events |
| `ENUM.REGISTRY` | 4 | Registry events |
| `ENUM.INJECTION` | 5 | Injection events |
| `ENUM.LOAD_IMAGE` | 6 | Image load events |
| `ENUM.USER_STATUS_CHANGE` | 7 | User status changes |
| `ENUM.TIME_CHANGE` | 8 | Time change events |
| `ENUM.THREAD` | 9 | Thread events |
| `ENUM.CAUSALITY` | 10 | Causality events |
| `ENUM.HOST_STATUS_CHANGE` | 11 | Host status changes |
| `ENUM.AGENT_STATUS_CHANGE` | 12 | Agent status changes |
| `ENUM.INTERNAL_STATISTICS` | 13 | Internal statistics |
| `ENUM.PROCESS_HANDLE` | 14 | Process handle events |
| `ENUM.EVENT_LOG` | 15 | Windows Event Log events |
| `ENUM.EPM_STATUS` | 16 | EPM status events |
| `ENUM.METADATA_CHANGE` | 17 | Metadata changes |
| `ENUM.SYSTEM_CALL` | 18 | System call events |
| `ENUM.DEVICE` | 19 | Device events |
| `ENUM.HOST_FIREWALL` | 23 | Host firewall events |
| `ENUM.STORY` | - | Network/Auth story events |
| `ENUM.VPN_EVENT` | - | VPN-specific events |

### XQL Filtering Behavior

**Important**: In XQL, `event_sub_type` values are **contextual** and depend on the `event_type`. The XQL editor provides dynamic suggestions based on your current filter context.

#### Example: Process Event Context
```sql
filter event_type = ENUM.PROCESS
| filter event_sub_type = ENUM.PROCESS_START  // ✅ Valid
// | filter event_sub_type = ENUM.FILE_CREATE  // ❌ Invalid - shows underline yellow warning
```

#### Example: File Event Context  
```sql
filter event_type = ENUM.FILE
| filter event_sub_type = ENUM.FILE_CREATE_NEW  // ✅ Valid
// | filter event_sub_type = ENUM.PROCESS_START   // ❌ Invalid - shows underline yellow warning
```

### Network/Authentication Events
**Filter**: `event_type = ENUM.STORY` or `event_type = ENUM.VPN_EVENT`

#### Story Events (`ENUM.STORY`)
**Filter**: `event_type = ENUM.STORY` | **Sub-filters**: `dfe_labels contains "authentication"`, `krb_tgt_data != null`, `ntlm_auth_data != null`
- **Authentication Stories**: Events with `dfe_labels` containing "authentication"
- **Network Stories**: General network connection events
- **Kerberos Stories**: Events with `krb_tgt_data` or `krb_tgs_data`
- **NTLM Stories**: Events with `ntlm_auth_data`

#### VPN Events (`ENUM.VPN_EVENT`)
**Filter**: `event_type = ENUM.VPN_EVENT`
- VPN connection establishment
- VPN session management
- VPN authentication events

### Endpoint Events

#### Process Events (`ENUM.PROCESS`)
**Filter**: `event_type = ENUM.PROCESS` | **Sub-types**: `ENUM.PROCESS_START`, `ENUM.PROCESS_STOP`
| Sub-Type | XDM Operation | Description |
|----------|---------------|-------------|
| `PROCESS_START` | `PROCESS_CREATE` | Process creation/launch |
| `PROCESS_STOP` | `PROCESS_TERMINATE` | Process termination |

#### File Events (`ENUM.FILE`)
**Filter**: `event_type = ENUM.FILE` | **Sub-types**: `ENUM.FILE_CREATE_NEW`, `ENUM.FILE_OPEN`, `ENUM.FILE_RENAME`, `ENUM.FILE_REMOVE`, `ENUM.FILE_WRITE`, etc.
| Sub-Type | XDM Operation | Description |
|----------|---------------|-------------|
| `FILE_CREATE_NEW` | `FILE_CREATE` | New file creation |
| `FILE_OPEN` | `FILE_OPEN` | File access/opening |
| `FILE_RENAME` | `FILE_RENAME` | File renaming |
| `FILE_LINK` | `FILE_LINK` | File linking |
| `FILE_REMOVE` | `FILE_REMOVE` | File deletion |
| `FILE_WRITE` | `FILE_WRITE` | File modification |
| `FILE_SET_ATTRIBUTE` | `FILE_SET_ATTRIBUTES` | File attribute changes |
| `FILE_DIR_CREATE` | `DIR_CREATE` | Directory creation |
| `FILE_DIR_OPEN` | `DIR_OPEN` | Directory access |
| `FILE_DIR_RENAME` | `DIR_RENAME` | Directory renaming |
| `FILE_DIR_LINK` | `DIR_LINK` | Directory linking |
| `FILE_DIR_REMOVE` | `DIR_REMOVE` | Directory deletion |
| `FILE_REPARSE` | `FILE_REPARSE` | File reparse operations |
| `FILE_SET_SECURITY_DESCRIPTOR` | `FILE_SET_SECURITY` | File security changes |
| `FILE_CHANGE_MODE` | `FILE_CHANGE_MODE` | File permission changes |
| `FILE_CHANGE_OWNER` | `FILE_CHANGE_OWNER` | File ownership changes |

#### Registry Events (`ENUM.REGISTRY`)
**Filter**: `event_type = ENUM.REGISTRY` | **Sub-types**: `ENUM.REGISTRY_CREATE_KEY`, `ENUM.REGISTRY_DELETE_KEY`, `ENUM.REGISTRY_SET_VALUE`, etc.
| Sub-Type | XDM Operation | Description |
|----------|---------------|-------------|
| `REGISTRY_CREATE_KEY` | `REGISTRY_CREATE_KEY` | Registry key creation |
| `REGISTRY_DELETE_KEY` | `REGISTRY_DELETE_KEY` | Registry key deletion |
| `REGISTRY_RENAME_KEY` | `REGISTRY_RENAME_KEY` | Registry key renaming |
| `REGISTRY_SET_VALUE` | `REGISTRY_SET_VALUE` | Registry value modification |
| `REGISTRY_DELETE_VALUE` | `REGISTRY_DELETE_VALUE` | Registry value deletion |
| `REGISTRY_LOAD` | `REGISTRY_LOAD` | Registry hive loading |
| `REGISTRY_UNLOAD` | `REGISTRY_UNLOAD` | Registry hive unloading |
| `REGISTRY_SAVE` | `REGISTRY_SAVE` | Registry save operations |
| `REGISTRY_RESTORE` | `REGISTRY_RESTORE` | Registry restore operations |

#### Load Image Events (`ENUM.LOAD_IMAGE`)
**Filter**: `event_type = ENUM.LOAD_IMAGE` | **Sub-types**: `ENUM.LOAD_IMAGE_MODULE`, `ENUM.LOAD_IMAGE_MPROTECT`, `ENUM.LOAD_IMAGE_PRELOAD`, etc.
| Sub-Type | XDM Operation | Description |
|----------|---------------|-------------|
| `LOAD_IMAGE_MODULE` | `IMAGE_LOAD` | Module/DLL loading |
| `LOAD_IMAGE_MPROTECT` | `IMAGE_MPROTECT` | Memory protection changes |
| `LOAD_IMAGE_PRELOAD` | `IMAGE_PRE_LOAD` | Pre-loading operations |
| `LOAD_IMAGE_SO_LOAD` | `IMAGE_SO_LOAD` | Shared object loading (Linux) |

## Operating System Support
**Filter**: `agent_os_type = ENUM.AGENT_OS_*` | **Values**: `ENUM.AGENT_OS_WINDOWS`, `ENUM.AGENT_OS_MAC`, `ENUM.AGENT_OS_LINUX`

### Supported OS Types
| OS Type | XDM Family | Description |
|---------|------------|-------------|
| `AGENT_OS_WINDOWS` | `OS_FAMILY_WINDOWS` | Windows systems |
| `AGENT_OS_MAC` | `OS_FAMILY_MACOS` | macOS systems |
| `AGENT_OS_LINUX` | `OS_FAMILY_LINUX` | Linux distributions |

### Agent Installation Types
**Filter**: `agent_install_type = ENUM.*` | **Values**: `ENUM.STANDARD`, `ENUM.VDI`, `ENUM.VDI_GOLDEN`, `ENUM.TEMPORARY_SESSION`, `ENUM.DATA_COLLECTOR`
| Install Type | XDM Agent Type | Use Case |
|--------------|----------------|----------|
| `STANDARD` | `AGENT_TYPE_REGULAR` | Standard endpoint deployment |
| `VDI` | `AGENT_TYPE_VDI` | Virtual desktop infrastructure |
| `VDI_GOLDEN` | `AGENT_TYPE_VDI` | VDI golden image |
| `TEMPORARY_SESSION` | `AGENT_TYPE_COLLECTOR` | Temporary data collection |
| `DATA_COLLECTOR` | `AGENT_TYPE_COLLECTOR` | Dedicated data collector |

## Story Type Classifications

### Authentication Stories
**Filters**: `dfe_labels contains "authentication"` | **Types**: `is_kerberos_story`, `is_ntlm_story`
- **Kerberos Authentication**: Ticket-based authentication
**Filters**: `krb_tgt_data != null` or `krb_tgs_data != null`
  - TGT (Ticket Granting Ticket) requests
  - TGS (Ticket Granting Service) requests
  - Error code mapping for failed authentications
  - Encryption type detection
  
- **NTLM Authentication**: Challenge-response authentication
**Filter**: `ntlm_auth_data != null`
  - Domain authentication
  - Local authentication
  - Challenge/response analysis

### Network Stories
**Filter**: `is_network_story = true` | **Protocols**: `action_network_protocol = ENUM.TCP/UDP/ICMP`
- **Application Protocol Detection**: HTTP, DNS, LDAP, RPC
- **Traffic Analysis**: Upload/download statistics
- **Connection Tracking**: Session duration and completion status
- **Proxy Detection**: Intermediate proxy identification

### VPN Stories
**Filter**: `is_vpn_story = true` | **Event Type**: `event_type = ENUM.VPN_EVENT`
- **Connection Events**: VPN session establishment
- **Authentication**: VPN user authentication
- **Client Information**: VPN client details and versions

## Field Mappings

### Core Event Fields
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `event_id` | `xdm.event.id` | Unique event identifier |
| `event_type` | `xdm.event.type` | Event category |
| `event_sub_type` | `xdm.event.operation_sub_type` | Specific operation |
| `insert_timestamp` | `_insert_time` | Event ingestion time |

### Host Information
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `agent_hostname` | `xdm.source.host.hostname` | Source hostname |
| `agent_id` | `xdm.source.host.device_id` | Source device ID |
| `agent_os_sub_type` | `xdm.source.host.os` | Detailed OS version |
| `agent_interface_map` | `xdm.source.host.ipv4_addresses` | Network interfaces |

### Process Information
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `actor_process_image_name` | `xdm.source.process.name` | Process executable name |
| `actor_process_image_path` | `xdm.source.process.executable.path` | Full executable path |
| `actor_process_os_pid` | `xdm.source.process.pid` | Process ID |
| `actor_process_command_line` | `xdm.source.process.command_line` | Command line arguments |

### Network Information
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_local_ip` | `xdm.source.ipv4` | Source IP address |
| `action_remote_ip` | `xdm.target.ipv4` | Destination IP address |
| `action_local_port` | `xdm.source.port` | Source port |
| `action_remote_port` | `xdm.target.port` | Destination port |

## Network Protocol Support
**Filter**: `action_network_protocol = ENUM.*` | **Values**: `ENUM.TCP`, `ENUM.UDP`, `ENUM.ICMP`

### Supported Protocols
- **HTTP/HTTPS**: Web traffic analysis
- **DNS**: Domain name resolution
- **LDAP**: Directory service queries
- **RPC**: Remote procedure calls
- **ICMP**: Network diagnostics
- **TCP/UDP**: Transport protocols

### Protocol-Specific Fields

#### HTTP
**Filter**: `http_method != null` | **Methods**: Various HTTP method ENUMs
- Request methods (GET, POST, PUT, DELETE, etc.)
- Response codes (200, 404, 500, etc.)
- Headers and content type
- URL categorization

#### DNS
**Filter**: `dns_query_name != null` | **Types**: Various DNS record type ENUMs
- Query types (A, AAAA, CNAME, MX, etc.)
- Response codes (NOERROR, NXDOMAIN, etc.)
- Resource records

#### LDAP
**Filter**: `ldap_data != null` | **Operations**: Various LDAP operation ENUMs
- Operations (BIND, SEARCH, MODIFY, etc.)
- Search scope (BASE, SINGLE_LEVEL, WHOLE_SUBTREE)
- Attributes and filters

## Authentication Methods
**Auth Method Filter**: `auth_method != null` | **Outcome Filter**: `auth_outcome = "SUCCESS"/"FAILURE"`

### Kerberos
- **Encryption Types**: DES, 3DES, AES128, AES256, RC4
- **Principal Types**: USER, SERVICE, HOST
- **Message Types**: AS_REQ, AS_REP, TGS_REQ, TGS_REP
- **Error Codes**: 30+ specific Kerberos error conditions

### NTLM
**Filter**: `ntlm_auth_data != null`
- **Challenge Data**: Client/server challenges
- **Domain Information**: DNS domain and NetBIOS names
- **Version Detection**: NTLM version identification

## File Operations
**Filter**: `event_type = ENUM.FILE` | **Signature Status**: `action_file_signature_status = ENUM.SIGNED/UNSIGNED`

### Supported File Types
| Type ID | Description |
|---------|-------------|
| 0 | Unknown |
| 1 | MZ (Executable) |
| 2 | PK (Zip file) |
| 3 | OLE (Compound Document) |
| 11 | PDF |
| 19 | ELF (Linux executable) |
| 20-21 | Mach-O (macOS executable) |

### File Signature Status
**Filter**: `action_file_signature_status = ENUM.*` | **Values**: `ENUM.SIGNED`, `ENUM.SIGNED_INVALID`, `ENUM.UNSIGNED`
- `SIGNED_VERIFIED`: Valid digital signature
- `SIGNED_INVALID`: Invalid or corrupted signature
- `UNSIGNED`: No digital signature
- `STATUS_UNKNOWN`: Signature status unclear

## Registry Operations
**Filter**: `event_type = ENUM.REGISTRY` | **Value Types**: `action_registry_value_type = ENUM.TYPE_*`

### Registry Value Types
- `REG_SZ`: String value
- `REG_EXPAND_SZ`: Expandable string
- `REG_BINARY`: Binary data
- `REG_DWORD`: 32-bit number
- `REG_QWORD`: 64-bit number
- `REG_MULTI_SZ`: Multiple strings

### Registry Keys
**Filter**: `action_registry_key_name != null` | **Common Paths**: Contains filters like `"\\Run"`, `"\\Services"`, etc.
- Full registry path mapping
- Value name and data extraction
- Before/after state tracking for modifications

## Event Outcome Mapping
**Filter**: `auth_outcome = "SUCCESS"/"FAILURE"` | **Network**: `action_network_success = true/false`

### Success/Failure Determination
- **Process Events**: Based on termination code
- **Registry Events**: Based on return value (0 = success)
- **Authentication Events**: Based on auth_outcome field
- **Network Events**: Based on connection success status

### Outcome Values
**XDM Mapping**: Maps to `XDM_CONST.OUTCOME_SUCCESS/FAILED/UNKNOWN`
- `OUTCOME_SUCCESS`: Operation completed successfully
- `OUTCOME_FAILED`: Operation failed
- `OUTCOME_UNKNOWN`: Outcome cannot be determined

## Data Enrichment
**Filters**: Various location and ASN filters | **Internal IP**: `is_internal_ip = true/false`

### Geolocation
- City, region, country mapping
- Latitude/longitude coordinates
- Timezone information
- Continent classification

### ASN Information
**Filter**: `action_as_data != null` | **Fields**: `as_number`, `organization`
- Autonomous System Number
- Organization name
- Network ownership details

### Threat Intelligence
**Filter**: `action_threat_ids != null` | **URL Category**: `dst_action_url_category != null`
- URL categorization
- File reputation scoring
- Threat ID association



## Best Practices

1. **Filtering**: Use appropriate event type filters to improve query performance
2. **Indexing**: Consider indexing frequently queried fields like timestamps and event types
3. **Data Retention**: Implement appropriate retention policies based on event criticality
4. **Monitoring**: Set up alerts for critical security events and authentication failures

## Advanced Features
**SSL Filter**: `ssl_data != null` | **Container Filter**: `actor_container_info != null` | **RPC Filter**: `action_rpc_items != null`

### SSL/TLS Analysis
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `ssl_data->ja3` | `xdm.network.tls.client_ja3` | Client TLS fingerprint |
| `ssl_data->ja3s` | `xdm.network.tls.server_ja3` | Server TLS fingerprint |
| `ssl_data->sni` | `xdm.network.tls.server_name` | Server Name Indication |

### Container Support
**Filter**: `actor_container_info != null` | **Target**: `dst_actor_container_info != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `actor_container_info->id` | `xdm.source.process.container_id` | Source container ID |
| `dst_actor_container_info->id` | `xdm.target.process.container_id` | Target container ID |

### RPC/DCE Operations
**Filter**: `action_rpc_items != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_rpc_items->interface_uuid` | `xdm.network.dcerpc.interface_uuid` | RPC interface identifier |
| `action_rpc_items->opnum` | `xdm.network.dcerpc.opnum` | RPC operation number |
| `action_rpc_items->req_svcctl_buffer` | `xdm.network.dcerpc.svcctl_buffer` | Service control buffer |

### ICMP Analysis
**Filter**: `icmp_code != null` and `icmp_type != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `icmp_code` | `xdm.network.icmp.code` | ICMP message code |
| `icmp_type` | `xdm.network.icmp.type` | ICMP message type |

## Detailed Protocol Mappings

### HTTP Status Code Classifications

#### 1xx Informational
- `100` - Continue
- `101` - Switching Protocols
- `102` - Processing
- `103` - Early Hints

#### 2xx Success
- `200` - OK
- `201` - Created
- `202` - Accepted
- `204` - No Content
- `206` - Partial Content

#### 3xx Redirection
- `301` - Moved Permanently
- `302` - Found
- `304` - Not Modified
- `307` - Temporary Redirect
- `308` - Permanent Redirect

#### 4xx Client Error
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests

#### 5xx Server Error
- `500` - Internal Server Error
- `502` - Bad Gateway
- `503` - Service Unavailable
- `504` - Gateway Timeout

### HTTP Methods Support
```
ACL, BASELINE_CONTROL, BIND, CHECKIN, CHECKOUT, CONNECT, COPY, DELETE,
GET, HEAD, LABEL, LINK, LOCK, MERGE, MKACTIVITY, MKCALENDAR, MKCOL,
MKREDIRECTREF, MKWORKSPACE, MOVE, OPTIONS, ORDERPATCH, PATCH, POST,
PRI, PROPFIND, PROPPATCH, PUT, REBIND, REPORT, SEARCH, TRACE, UNBIND,
UNCHECKOUT, UNLINK, UNLOCK, UPDATE, UPDATEREDIRECTREF, VERSION_CONTROL
```

### DNS Record Types Support
```
A, AAAA, AFSDB, APL, CAA, CDNSKEY, CDS, CERT, CNAME, CSYNC, DHCID,
DLV, DNAME, DNSKEY, DS, EUI48, EUI64, HINFO, HIP, HTTPS, IPSECKEY,
KEY, KX, LOC, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY,
PTR, RRSIG, RP, SIG, SMIMEA, SOA, SRV, SSHFP, SVCB, TA, TKEY,
TLSA, TSIG, TXT, URI, ZONEMD
```

### DNS Response Codes
| Code | XDM Constant | Description |
|------|--------------|-------------|
| No error | `DNS_RESPONSE_CODE_NO_ERROR` | Successful query |
| Format Error | `DNS_RESPONSE_CODE_FORMAT_ERROR` | Malformed query |
| Server Failure | `DNS_RESPONSE_CODE_SERVER_FAILURE` | Server error |
| Non-Existent Domain | `DNS_RESPONSE_CODE_NON_EXISTENT_DOMAIN` | Domain not found |
| Not Implemented | `DNS_RESPONSE_CODE_NOT_IMPLEMENTED` | Query type not supported |
| Query Refused | `DNS_RESPONSE_CODE_QUERY_REFUSED` | Server refused query |

## Authentication Deep Dive

### Kerberos Encryption Types
| Type ID | Algorithm | Security Level |
|---------|-----------|----------------|
| 1 | DES-CBC-CRC | **Deprecated** |
| 3 | DES-CBC-MD5 | **Deprecated** |
| 17 | AES128-CTS-HMAC-SHA1-96 | **Recommended** |
| 18 | AES256-CTS-HMAC-SHA1-96 | **Recommended** |
| 23 | RC4-HMAC | **Legacy** |

### Kerberos Principal Types
| Type ID | XDM Constant | Description |
|---------|--------------|-------------|
| 0 | `KERBEROS_PRINCIPAL_TYPE_UNKNOWN` | Unknown principal |
| 1 | `KERBEROS_PRINCIPAL_TYPE_PRINCIPAL` | User principal |
| 2 | `KERBEROS_PRINCIPAL_TYPE_SRV_INST` | Service instance |
| 3 | `KERBEROS_PRINCIPAL_TYPE_SRV_HST` | Service host |
| 10 | `KERBEROS_PRINCIPAL_TYPE_ENTERPRISE` | Enterprise principal |

### Kerberos Error Codes (Key Examples)
| Code | XDM Constant | Description |
|------|--------------|-------------|
| 6 | `ERR_KDC_C_PRINCIPAL_UNKNOWN` | Client principal unknown |
| 7 | `ERR_KDC_S_PRINCIPAL_UNKNOWN` | Service principal unknown |
| 18 | `ERR_KDC_CLIENT_REVOKED` | Client credentials revoked |
| 24 | `ERR_KDC_PREAUTH_FAILED` | Pre-authentication failed |
| 25 | `ERR_KDC_PREAUTH_REQUIRED` | Pre-authentication required |
| 32 | `ERR_AP_TKT_EXPIRED` | Ticket expired |

### Kerberos Pre-Authentication Types
| Type ID | XDM Constant | Description |
|---------|--------------|-------------|
| 2 | `KERBEROS_PA_TYPE_ENC_TIMESTAMP` | Encrypted timestamp |
| 11 | `KERBEROS_PA_TYPE_ETYPE_INFO` | Encryption type info |
| 19 | `KERBEROS_PA_TYPE_ETYPE_INFO2` | Enhanced encryption type info |
| 128 | `KERBEROS_PA_TYPE_PAC_REQUEST` | PAC request |
| 138 | `KERBEROS_PA_TYPE_ENCRYPTED_CHALLENGE` | Encrypted challenge |

### Kerberos KDC Options
| Bit | XDM Constant | Description |
|-----|--------------|-------------|
| 1 | `KERBEROS_KDC_OPTION_FORWARDABLE` | Ticket is forwardable |
| 2 | `KERBEROS_KDC_OPTION_FORWARDED` | Ticket is forwarded |
| 3 | `KERBEROS_KDC_OPTION_PROXIABLE` | Ticket is proxiable |
| 8 | `KERBEROS_KDC_OPTION_RENEWABLE` | Ticket is renewable |
| 15 | `KERBEROS_KDC_OPTION_CANONICALIZE` | Canonicalize principal |

## LDAP Operations Detail
**Filter**: `ldap_data != null` | **Operation**: `ldap_data->operation`, **Scope**: `ldap_data->scope`

### LDAP Operations
| Operation | XDM Constant | Direction |
|-----------|--------------|-----------|
| BindRequest | `LDAP_OPERATION_BIND_REQUEST` | Client → Server |
| BindResponse | `LDAP_OPERATION_BIND_RESPONSE` | Server → Client |
| SearchRequest | `LDAP_OPERATION_SEARCH_REQUEST` | Client → Server |
| SearchResultEntry | `LDAP_OPERATION_SEARCH_RESULT_ENTRY` | Server → Client |
| SearchResultDone | `LDAP_OPERATION_SEARCH_RESULT_DONE` | Server → Client |
| ModifyRequest | `LDAP_OPERATION_MODIFY_REQUEST` | Client → Server |
| AddRequest | `LDAP_OPERATION_ADD_REQUEST` | Client → Server |
| DelRequest | `LDAP_OPERATION_DEL_REQUEST` | Client → Server |

### LDAP Search Scopes
**Filter**: `ldap_data->scope = "baseObject"/"singleLevel"/"wholeSubtree"`
| Scope | XDM Constant | Description |
|-------|--------------|-------------|
| baseObject | `LDAP_SCOPE_BASE_OBJECT` | Search only the base DN |
| singleLevel | `LDAP_SCOPE_SINGLE_LEVEL` | Search one level below base |
| wholeSubtree | `LDAP_SCOPE_WHOLE_SUBTREE` | Search entire subtree |

### LDAP Authentication Types
**Filter**: `auth_service = "simple"/"sasl"`
| Type | XDM Constant | Description |
|------|--------------|-------------|
| simple | `LDAP_BIND_AUTH_TYPE_SIMPLE` | Simple bind (username/password) |
| sasl | `LDAP_BIND_AUTH_TYPE_SASL` | SASL authentication |

## VPN and Remote Access
**Filter**: `event_type = ENUM.VPN_EVENT` | **VPN Server**: `vpn_server != null`

### VPN Event Fields
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `vpn_event_description` | `xdm.event.description` | VPN event description |
| `vpn_server` | `xdm.intermediate.host.hostname` | VPN server hostname |
| `client_version_str` | `xdm.source.application.version` | VPN client version |
| `checkpoint_vpn_data->client_application` | `xdm.target.application.name` | VPN client application |

### Hardware and Device Identification
**Filter**: `hardware_id != null` | **Device Category**: `device_id->category != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `hardware_id` | `xdm.source.host.hardware_uuid` | Hardware UUID |
| `device_id->category` | `xdm.source.host.device_category` | Device category |
| `device_id->model` | `xdm.source.host.device_model` | Device model |
| `device_id->vendor` | `xdm.source.host.manufacturer` | Device manufacturer |
| `device_id->mac` | `xdm.source.host.device_id` | Device MAC address |

## File System Operations
**Filter**: `event_type = ENUM.FILE` | **File Type**: `action_file_type = 0-34`

### Extended File Types
| Type ID | Description | Common Extensions |
|---------|-------------|-------------------|
| 5 | LNK | .lnk |
| 7 | EML | .eml |
| 10 | RTF | .rtf |
| 12 | JavaClass | .class |
| 15 | GZ | .gz |
| 22 | Shabang | Scripts with #! |
| 23 | RPM | .rpm |
| 24 | DEB | .deb |
| 29 | Shell | .sh |
| 30 | Python | .py |
| 31 | Perl | .pl |
| 33 | WinMemDmp | .dmp |
| 34 | VBE | .vbe |

### File Operation Context
**Before State**: `action_file_previous_*` fields | **After State**: `action_file_*` fields
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_file_previous_file_name` | `xdm.target.file_before.filename` | Original filename |
| `action_file_previous_file_path` | `xdm.target.file_before.path` | Original file path |
| `action_file_previous_file_extension` | `xdm.target.file_before.extension` | Original file extension |

### Module Loading Analysis
**Filter**: `event_type = ENUM.LOAD_IMAGE` | **Module Path**: `action_module_path != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_module_path` | `xdm.target.module.path` | Module full path |
| `action_module_md5` | `xdm.target.module.md5` | Module MD5 hash |
| `action_module_sha256` | `xdm.target.module.sha256` | Module SHA256 hash |
| `action_module_signature_vendor` | `xdm.target.module.signer` | Module signer |

## Process Relationships
**Filter**: `event_type = ENUM.PROCESS` | **Causality**: `actor_process_causality_id != null`

### Process Hierarchy
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `actor_process_instance_id` | `xdm.source.process.identifier` | Process instance ID |
| `action_process_requested_parent_iid` | `xdm.target.process.parent_id` | Parent process ID |
| `os_actor_process_causality_id` | `xdm.source.process.causality_id` | Process causality chain |

### Process Security Context
**Integrity Level**: `actor_process_integrity_level != null` | **Injection**: `actor_is_injected_thread = true`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `actor_process_integrity_level` | `xdm.source.process.integrity_level` | Process integrity level |
| `actor_primary_user_sid` | `xdm.source.user.identifier` | User SID |
| `actor_is_injected_thread` | `xdm.source.process.is_injected` | Code injection detection |

### Thread Information
**Filter**: `actor_thread_thread_id != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `actor_thread_thread_id` | `xdm.source.process.thread_id` | Thread identifier |
| `dst_actor_thread_thread_id` | `xdm.target.process.thread_id` | Target thread ID |

## Network Traffic Analysis
**Filter**: `is_network_story = true` | **Session**: `action_session_duration != null`

### Traffic Statistics
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_total_upload` | `xdm.source.sent_bytes` | Total bytes uploaded |
| `action_total_download` | `xdm.target.sent_bytes` | Total bytes downloaded |
| `action_pkts_sent` | `xdm.source.sent_packets` | Packets sent count |
| `action_pkts_received` | `xdm.target.sent_packets` | Packets received count |

### Session Analysis
**Duration**: `action_session_duration != null` | **Completion**: `action_network_stats_is_last = true/false`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_session_duration` | `xdm.event.duration` | Session duration |
| `action_network_stats_is_last` | `xdm.event.is_completed` | Session completion status |
| `story_id` | `xdm.network.session_id` | Network session ID |

### Proxy and NAT Detection
**Proxy**: `action_proxy = true` | **NAT**: `action_nat = true`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_proxy` | `xdm.intermediate.is_proxy` | Proxy detection |
| `action_nat` | `xdm.intermediate.is_nat` | NAT detection |
| `action_external_port` | `xdm.target.port` | External port (via proxy) |

## User and Identity Management
**Filter**: `auth_normalized_user != null` | **Identity Type**: `auth_normalized_user->identity_type`

### User Identity Types
Mapped through `auth_normalized_user->identity_type`:
- Domain users
- Local users
- Service accounts
- Computer accounts

### User Attributes
**UPN**: `auth_normalized_user->upn != null` | **Domain**: `auth_normalized_user->domain != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `auth_normalized_user->upn` | `xdm.source.user.upn` | User Principal Name |
| `auth_normalized_user->username` | `xdm.source.user.sam_account_name` | SAM account name |
| `auth_normalized_user->domain` | `xdm.source.user.netbios_domain` | NetBIOS domain |
| `auth_normalized_user->scope` | `xdm.source.user.scope` | User scope |

## Geographic and Network Intelligence
**Location Filter**: `action_location != null` | **ASN Filter**: `action_as_data != null`

### ASN (Autonomous System) Information
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_as_data->as_number` | `xdm.source.asn.as_number` | AS number |
| `action_as_data->organization` | `xdm.source.asn.as_name` | Organization name |
| `dst_action_as_data->as_number` | `xdm.target.asn.as_number` | Target AS number |

### Geolocation Data
**City**: `action_location->city != null` | **Country**: `action_location->country != "-"`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_location->city` | `xdm.source.location.city` | Source city |
| `action_location->region` | `xdm.source.location.region` | Source region/state |
| `action_location->country` | `xdm.source.location.country` | Source country |
| `action_location->continent` | `xdm.source.location.continent` | Source continent |
| `action_location->latitude` | `xdm.source.location.latitude` | Latitude coordinates |
| `action_location->longitude` | `xdm.source.location.longitude` | Longitude coordinates |
| `action_location->timezone` | `xdm.source.location.timezone` | Timezone information |

## Alert and Threat Context
**Threat IDs**: `action_threat_ids != null` | **Severity**: `file_data->severity != null`

### Alert Information
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `action_threat_ids` | `xdm.alert.original_alert_id` | Threat detection IDs |
| `file_data->severity` | `xdm.alert.severity` | Alert severity level |

### URL and Content Analysis
**URL Category**: `dst_action_url_category != null` | **User Agent**: `action_user_agent != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `dst_action_url_category` | `xdm.network.http.url_category` | URL category |
| `action_user_agent` | `xdm.source.user_agent` | HTTP User-Agent |
| `http_referer` | `xdm.network.http.referrer` | HTTP Referer header |

## Observer and Metadata
**Content Version**: `agent_content_version != null` | **Story Version**: `story_version != null`

### Content Versioning
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `agent_content_version` | `xdm.observer.content_version` | Detection content version |
| `story_version` | `xdm.observer.version` | Story format version |
| `_product` | `xdm.observer.product` | Product identifier |
| `_vendor` | `xdm.observer.vendor` | Vendor identifier |

### Rule and Policy Context
**Rule**: `backtrace_identities->rule != null` | **Action**: `backtrace_identities->action != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `backtrace_identities->rule` | `xdm.network.rule` | Triggered rule |
| `backtrace_identities->action` | `xdm.observer.action` | Action taken |
| `backtrace_identities->serial` | `xdm.observer.unique_identifier` | Observer serial |

### Network Zones
**Source Zone**: `backtrace_identities->interface_from != null` | **Target Zone**: `backtrace_identities->interface_to != null`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `backtrace_identities->interface_from` | `xdm.source.zone` | Source network zone |
| `backtrace_identities->interface_to` | `xdm.target.zone` | Target network zone |

## Advanced Security Features
**MFA**: `auth_mfa_needed != null` | **Association**: `association_strength > 10`

### MFA Detection
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `auth_mfa_needed` | `xdm.auth.is_mfa_needed` | MFA requirement flag |

### Association Strength
Used for device correlation:
- `association_strength > 10`: Strong device association
- `dst_association_strength > 10`: Strong target device association

### Internal/External Classification
**Source Internal**: `is_internal_ip = true/false` | **Target Internal**: `dst_is_internal_ip = true/false`
| Source Field | XDM Field | Description |
|--------------|-----------|-------------|
| `is_internal_ip` | `xdm.source.is_internal_ip` | Source IP internal flag |
| `dst_is_internal_ip` | `xdm.target.is_internal_ip` | Target IP internal flag |

## Data Processing Logic
**IPv4/IPv6**: `action_network_is_ipv6 = true/false` | **Proxy**: `action_proxy = true/false`

### IPv4/IPv6 Handling
```sql
-- IPv4 assignment logic
xdm.source.ipv4 = if(action_network_is_ipv6=False, action_local_ip)
xdm.target.ipv4 = if(action_network_is_ipv6=False, action_remote_ip)

-- IPv6 assignment logic  
xdm.source.ipv6 = if(action_network_is_ipv6=True, action_local_ip)
xdm.target.ipv6 = if(action_network_is_ipv6=True, action_remote_ip)
```

### Proxy Detection Logic
```sql
-- Intermediate fields populated when proxy detected
xdm.intermediate.ipv4 = if(action_network_is_ipv6=False and action_proxy=True, action_remote_ip)
xdm.intermediate.port = if(action_proxy=True, action_remote_port)
```

### Directory Extraction Logic
```sql
-- Cross-platform directory extraction
if(path contains "/", arrayindex(split(path, "/"), -2),     -- Unix-style
   path contains "\\", arrayindex(split(path, "\\"), -2),   -- Windows-style
   path)                                                     -- Fallback
```

## XQL Query Examples and Best Practices

### Dynamic Filtering and Autocomplete

XQL provides **context-aware suggestions** based on your current filters. This helps prevent invalid queries and guides you toward valid ENUM combinations.

#### How It Works:
1. **Filter by event_type**: Narrows available `event_sub_type` options
2. **Autocomplete suggestions**: Only shows valid ENUMs for current context  
3. **Real-time validation**: Yellow underlines warn of invalid ENUM combinations

#### Example: Process Event Filtering
```sql
// Start with process events
filter event_type = ENUM.PROCESS

// Now autocomplete will only suggest process-related subtypes:
// - ENUM.PROCESS_START
// - ENUM.PROCESS_STOP
| filter event_sub_type = ENUM.PROCESS_START

// Additional process-specific filters
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
```

#### Example: File Event Filtering  
```sql
// Start with file events
filter event_type = ENUM.FILE

// Autocomplete suggests file-related subtypes:
// - ENUM.FILE_CREATE_NEW
// - ENUM.FILE_WRITE
// - ENUM.FILE_RENAME
// - ENUM.FILE_REMOVE
| filter event_sub_type = ENUM.FILE_CREATE_NEW
```

### Common XQL Patterns

#### Security Monitoring Queries

**Unsigned Process Execution**
```sql
filter event_type = ENUM.PROCESS 
and event_sub_type = ENUM.PROCESS_START
and actor_process_signature_status = ENUM.UNSIGNED
| fields agent_hostname, actor_process_image_name, actor_process_image_path
```

**External Network Connections**
```sql
filter event_type = ENUM.STORY
and is_network_story = true
and dst_is_internal_ip = false
| fields actor_process_image_name, action_remote_ip, dst_action_location
```

**Failed Authentication Events**
```sql
filter event_type = ENUM.STORY  
and dfe_labels contains "authentication"
and auth_outcome = "FAILURE"
| fields auth_client, auth_server, auth_outcome_reason
```

**Registry Persistence Mechanisms**
```sql
filter event_type = ENUM.REGISTRY
and event_sub_type = ENUM.REGISTRY_SET_VALUE
and action_registry_key_name contains "\\Run"
| fields actor_process_image_name, action_registry_key_name, action_registry_value_name
```

#### Performance and Volume Analysis

**High-Volume Process Activity**
```sql
filter event_type = ENUM.PROCESS
and _insert_time > current_time() - interval 1 hour
| fields actor_process_image_name
| stats count() by actor_process_image_name
| sort count desc
| limit 10
```

**Network Traffic by Destination**
```sql
filter event_type = ENUM.STORY
and is_network_story = true  
and _insert_time > current_time() - interval 24 hours
| fields action_remote_ip, action_total_upload, action_total_download
| stats sum(action_total_upload) as total_upload, sum(action_total_download) as total_download by action_remote_ip
| sort total_upload + total_download desc
```

### XQL Editor Validation

#### Understanding Yellow Underlines
When you see a **yellow underline** under an ENUM in the XQL editor:

❌ **Invalid**: The ENUM doesn't match your current filter context
```sql
filter event_type = ENUM.FILE
| filter event_sub_type = ENUM.PROCESS_START  // Yellow underline warning
```

✅ **Valid**: The ENUM is appropriate for your filter context  
```sql
filter event_type = ENUM.FILE
| filter event_sub_type = ENUM.FILE_CREATE_NEW  // No warning
```

#### Filter Context Effects

| What You Filter | Next Suggestions Include |
|-----------------|-------------------------|
| `event_type = ENUM.PROCESS` | Only process subtypes (PROCESS_START, PROCESS_STOP) |
| `event_type = ENUM.FILE` | Only file subtypes (FILE_CREATE_NEW, FILE_WRITE, etc.) |
| `event_type = ENUM.REGISTRY` | Only registry subtypes (REGISTRY_SET_VALUE, etc.) |
| `agent_os_type = ENUM.AGENT_OS_WINDOWS` | Windows-specific fields and values |

### Security Monitoring Queries

 

### Performance Queries

#### High Volume Process Activity
```sql
filter event_type = ENUM.PROCESS
and _insert_time > current_time() - interval 1 hour
| fields actor_process_image_name
| stats count() by actor_process_image_name
| sort count desc
| limit 10
```

#### Network Traffic Analysis
```sql
filter event_type = ENUM.STORY
and is_network_story = true
and _insert_time > current_time() - interval 24 hours
| fields action_remote_ip, action_total_upload, action_total_download
| stats sum(action_total_upload) as total_upload, sum(action_total_download) as total_download by action_remote_ip
| sort total_upload + total_download desc
```

### Data Quality and Validation

### Required Field Validation
- All events must have `event_id`, `event_type`, and `_insert_time`
- Network stories require `action_local_ip` and `action_remote_ip`
- Process events require `actor_process_image_name` and `actor_process_os_pid`
- Authentication events require `auth_outcome`

### XQL Data Consistency Checks

#### Missing Geolocation Data
```sql
filter event_type = ENUM.STORY
and is_network_story = true 
and dst_action_location->country = null
| stats count()
```

#### Signature Status Anomalies
```sql
filter event_type = ENUM.PROCESS
and actor_process_signature_status = ENUM.SIGNED
and actor_process_signature_vendor = null
| fields actor_process_image_name, actor_process_signature_status, actor_process_signature_vendor
```

#### Authentication Correlation Issues
```sql
filter event_type = ENUM.STORY
and is_kerberos_story = true
and auth_identity = null
| stats count()
```

## Troubleshooting

### Common XQL Issues

#### ENUM Validation Errors
**Problem**: Yellow underline on ENUM constants
**Solution**: Ensure ENUM matches current filter context

```sql
// ❌ This will show a yellow warning
filter event_type = ENUM.FILE
| filter event_sub_type = ENUM.PROCESS_START

// ✅ This is correct 
filter event_type = ENUM.FILE
| filter event_sub_type = ENUM.FILE_CREATE_NEW
```

#### Missing Geolocation Data
```sql
// Check for events without location data
filter event_type = ENUM.STORY
and is_network_story = true 
and dst_action_location->country = null
| stats count()
```

#### Signature Status Anomalies
```sql
// Find processes with inconsistent signature data
filter event_type = ENUM.PROCESS
and actor_process_signature_status = ENUM.SIGNED
and actor_process_signature_vendor = null
| fields actor_process_image_name, actor_process_signature_status, actor_process_signature_vendor
```

#### Authentication Correlation Issues
```sql
// Check for Kerberos events missing user data
filter event_type = ENUM.STORY
and is_kerberos_story = true
and auth_identity = null
| stats count()
```

### XQL Performance Optimization

#### Effective Filtering Strategies
1. **Start with event_type**: Always filter by `event_type` first
2. **Use time windows**: Include `_insert_time` filters for recent data
3. **Leverage ENUMs**: Use ENUM constants instead of string literals
4. **Context-aware queries**: Let XQL autocomplete guide valid combinations

#### Example: Optimized Query Structure
```sql
// ✅ Efficient: Filter by type first, then narrow down
filter event_type = ENUM.PROCESS
and _insert_time > current_time() - interval 1 hour  
and event_sub_type = ENUM.PROCESS_START
and agent_os_type = ENUM.AGENT_OS_WINDOWS
| fields actor_process_image_name, actor_process_image_path
```

```sql
// ❌ Less efficient: Avoid broad filters without event_type
filter actor_process_image_name contains "powershell"
and _insert_time > current_time() - interval 1 hour
```



### Understanding Data Model Rules
The relationships between `event_type` and `event_sub_type` are defined in **Data Model Rules** - the logic that maps raw telemetry into normalized XDM fields. These rules ensure that:

1. **Correct ENUMs are assigned** based on raw log content
2. **Context-dependent suggestions** work in the XQL editor  
3. **Invalid combinations** are flagged with yellow underlines
4. **Normalized data** maintains consistency across different log sources

