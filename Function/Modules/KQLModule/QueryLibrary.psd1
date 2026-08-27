@{
    # Each entry: template name -> @{ Query = <KQL with {ParamName} placeholders>; RequiredParam = <name>; ParamEntityType = <entity type it must come from> }
    'SigninsByAccount' = @{
        Query = "SigninLogs | where TimeGenerated > ago(14d) | where UserPrincipalName == TargetAccount | project TimeGenerated, IPAddress, AppDisplayName, ResultType, Location | take 200"
        RequiredParam = 'TargetAccount'
        ParamEntityType = 'account'
    }
    'ActivityByIp' = @{
        Query = "CommonSecurityLog | where TimeGenerated > ago(14d) | where SourceIP == TargetIp or DestinationIP == TargetIp | summarize Count = count() by SourceIP, DestinationIP, DeviceAction | take 200"
        RequiredParam = 'TargetIp'
        ParamEntityType = 'ip'
    }
    'ProcessEventsByHost' = @{
        Query = "DeviceProcessEvents | where TimeGenerated > ago(7d) | where DeviceName == TargetHost | project TimeGenerated, FileName, ProcessCommandLine, AccountName | take 200"
        RequiredParam = 'TargetHost'
        ParamEntityType = 'host'
    }
}
