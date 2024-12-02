@{
    ObserveEndpoint = "URL_HERE"
    ObserveToken = "TOKEN_HERE"
    TempDir = "TEMP_PATH_HERE"
    RetryAttempts = 3
    RetryDelaySeconds = 5
    LogFormats = @{
        AzureActivityLogs = "JSON"
        DirectoryActivityLogs = "CSV"
        UAL = "CSV"
        UALStatistics = "CSV"
        MessageTraceLogs = "CSV"
        MailboxAuditLogs = "CSV"
        AdminAuditLogs = "CSV"
        MailboxRules = "CSV"
        TransportRules = "CSV"
        Users = "CSV"
        AdminUsers = "CSV"
        MFA = "CSV"
        RiskyUsers = "CSV"
        RiskyDetections = "CSV"
        ConditionalAccessPolicies = "CSV"
        ADSignInLogs = "JSON"
        ADAuditLogs = "JSON"
        EmailSessions = "CSV"
    }
} 
