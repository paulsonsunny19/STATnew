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
    # Overpass-the-hash (Mimikatz sekurlsa::pth and similar) forges a Kerberos TGT request
    # from an NTLM hash. Because the tool doesn't have the account's AES key, the resulting
    # 4768/4769 tickets are typically requested with legacy RC4 encryption (0x17/0x18) even on
    # accounts/domains where AES is otherwise the norm - the same downgrade signal used by
    # "Possible overpass-the-hash attack" style alerts. Surface those events for the flagged account.
    'OverpassTheHashIndicatorsByAccount' = @{
        Query = "SecurityEvent | where TimeGenerated > ago(14d) | where TargetUserName == TargetAccount | where EventID in (4768, 4769) | where TicketEncryptionType in ('0x17', '0x18') | project TimeGenerated, Computer, IpAddress, EventID, TicketEncryptionType, TargetUserName, ServiceName | take 200"
        RequiredParam = 'TargetAccount'
        ParamEntityType = 'account'
    }
}
