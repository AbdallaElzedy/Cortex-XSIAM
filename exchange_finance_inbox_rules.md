```
dataset = msft_o365_exchange_online_raw 
| filter _time > to_timestamp(subtract(to_epoch(current_time()), 2592000), "SECONDS")
| filter Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "UpdateInboxRules", "Remove-InboxRule", "Disable-InboxRule", "Get-InboxRule")
| alter parameters_array = json_extract_array(to_json_string(Parameters), "$")
| alter AlwaysDeleteOutlookRulesBlob = json_extract_scalar(to_json_string(arrayindex(parameters_array, 0)), "$.Value"),
         Force = json_extract_scalar(to_json_string(arrayindex(parameters_array, 1)), "$.Value"),
         Identity = json_extract_scalar(to_json_string(arrayindex(parameters_array, 2)), "$.Value"),
         From = json_extract_scalar(to_json_string(arrayindex(parameters_array, 3)), "$.Value"),
         RuleName = json_extract_scalar(to_json_string(arrayindex(parameters_array, 4)), "$.Value"),
         SubjectContainsWords = json_extract_scalar(to_json_string(arrayindex(parameters_array, 5)), "$.Value"),
         StopProcessingRules = json_extract_scalar(to_json_string(arrayindex(parameters_array, 6)), "$.Value")
| alter combined_fields = lowercase(concat(From, " ", RuleName, " ", SubjectContainsWords, " ", Identity))
| filter string_count(combined_fields, "accounting") > 0 or
         string_count(combined_fields, "agreement") > 0 or
         string_count(combined_fields, "bank") > 0 or
         string_count(combined_fields, "bic") > 0 or
         string_count(combined_fields, "capital call") > 0 or
         string_count(combined_fields, "cash") > 0 or
         string_count(combined_fields, "confidential") > 0 or
         string_count(combined_fields, "contribution") > 0 or
         string_count(combined_fields, "credentials") > 0 or
         string_count(combined_fields, "credit") > 0 or
         string_count(combined_fields, "deposit") > 0 or
         string_count(combined_fields, "dividend") > 0 or
         string_count(combined_fields, "docusign") > 0 or
         string_count(combined_fields, "finance") > 0 or
         string_count(combined_fields, "fund") > 0 or
         string_count(combined_fields, "iban") > 0 or
         string_count(combined_fields, "invoice") > 0 or
         string_count(combined_fields, "password") > 0 or
         string_count(combined_fields, "payment") > 0 or
         string_count(combined_fields, "payroll") > 0 or
         string_count(combined_fields, "purchase") > 0 or
         string_count(combined_fields, "sensitive") > 0 or
         string_count(combined_fields, "shares") > 0 or
         string_count(combined_fields, "ssn") > 0 or
         string_count(combined_fields, "statement") > 0 or
         string_count(combined_fields, "swift") > 0 or
         string_count(combined_fields, "tax") > 0 or
         string_count(combined_fields, "transfer") > 0 or
         string_count(combined_fields, "w2") > 0 or
         string_count(combined_fields, "wire") > 0 or
         string_count(combined_fields, "wiring info") > 0 or
         string_count(combined_fields, "withdrawal") > 0
| alter ClientIP = arrayindex(split(ClientIP, ":"), 0)
| iploc ClientIP suffix = _geo
| alter latitude = arrayindex(split(loc_latlon_geo, ","), 0), longitude = arrayindex(split(loc_latlon_geo, ","), 1)
| sort desc _time
| alter location = concat(loc_city_geo ,", ",loc_region_geo)
| fields _time, Operation, UserId, ClientIP, From, RuleName, Identity, location , loc_asn_org_geo as ASN  
| view highlight fields = RuleName, From, Identity  values = "accounting", "agreement", "bank", "bic", "capital call", "cash", "confidential", "contribution", "credentials", "credit", "deposit", "dividend", "docusign", "finance", "fund",  "invoice", "password", "payment", "payroll", "purchase", "sensitive", "shares", "ssn", "statement", "swift", "tax", "transfer", "w2", "wire", "wiring info", "withdrawal"
```
