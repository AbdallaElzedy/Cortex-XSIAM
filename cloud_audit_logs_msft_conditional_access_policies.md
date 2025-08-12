``` cloud_audit_logs_msft_conditional_access_policies.md
dataset = cloud_audit_logs
//| filter identity_name =    ""
| filter log_name = "azure_ad_signin_logs"
| alter raw_json = to_json_string(raw_log)
| alter conditionalAccessStatus = json_extract(raw_json, "$.properties.conditionalAccessStatus")
| alter appliedPolicies = json_extract_array(raw_json, "$.properties.appliedConditionalAccessPolicies")
| alter successPolicies = arrayfilter(appliedPolicies, json_extract_scalar("@element", "$.result") = "success")
| alter failedPolicies = arrayfilter(appliedPolicies, json_extract_scalar("@element", "$.result") = "failure") 
| alter notAppliedPolicies = arrayfilter(appliedPolicies, json_extract_scalar("@element", "$.result") = "notApplied")
| alter reportOnlyPolicies = arrayfilter(appliedPolicies, json_extract_scalar("@element", "$.result") = "reportOnlyNotApplied")
| alter success_names = arraymap(successPolicies, json_extract_scalar("@element", "$.displayName"))
| alter failed_names = arraymap(failedPolicies, json_extract_scalar("@element", "$.displayName"))
| alter not_applied_names = arraymap(notAppliedPolicies, json_extract_scalar("@element", "$.displayName"))
| alter report_only_names = arraymap(reportOnlyPolicies, json_extract_scalar("@element", "$.displayName"))
| fields _time, identity_name,referenced_resource_name,  conditionalAccessStatus, success_names, failed_names, not_applied_names, report_only_names
| sort desc _time

```
