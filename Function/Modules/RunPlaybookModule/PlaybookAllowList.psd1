@{
    # Logical name -> Key Vault secret holding that playbook's callback trigger URL (SAS-signed).
    # The trigger URL itself is never stored in code or app settings, only its Key Vault secret name.
    'IsolateDevice'      = 'playbook-trigger-isolatedevice'
    'DisableAccount'     = 'playbook-trigger-disableaccount'
    'BlockIpAddress'     = 'playbook-trigger-blockip'
    'NotifySocTeams'     = 'playbook-trigger-notifysoc'
}
