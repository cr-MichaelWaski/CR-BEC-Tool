# Script parameters
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [DateTime]$StartDate,
    
    [Parameter(Mandatory=$false)]
    [DateTime]$EndDate = (Get-Date),
    
    [Parameter(Mandatory=$false)]
    [string[]]$EmailAddresses,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\config.psd1",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Users", "AdminUsers", "MFA", "RiskyUsers", "RiskyDetections", "ConditionalAccessPolicies", "OAuthPermissions", "ADSignInLogs", "ADAuditLogs", "MailboxRules", "TransportRules", "AdminAuditLogs", "MailboxAuditLogs", "MessageTraceLogs", "AzureActivityLogs", "DirectoryActivityLogs", "UALStatistics", "UAL", "EmailSessions")]
    [string[]]$LogTypes = @("All"),

    [Parameter(Mandatory=$false)]
    [switch]$EnableDebug
)

# Configuration class with validation
class Config {
    [string]$ObserveEndpoint
    [string]$ObserveToken
    [string]$TempDir
    [int]$RetryAttempts = 3
    [int]$RetryDelaySeconds = 15
    [hashtable]$LogFormats

    Config() {
        $scriptPath = $PSScriptRoot
        $this.TempDir = Join-Path $scriptPath "ExtractorTemp"
    }

    [void]Validate() {
        if ([string]::IsNullOrEmpty($this.ObserveEndpoint)) { throw "ObserveEndpoint is required" }
        if ([string]::IsNullOrEmpty($this.ObserveToken)) { throw "ObserveToken is required" }
        if (-not $this.LogFormats) { throw "LogFormats configuration is missing" }
    }
}

# Logging module
class Logger {
    static [void] Write([string]$Message, [string]$Level = "INFO") {
        if ($Level -eq "DEBUG" -and -not $script:EnableDebug) { return }
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

# Configuration manager
class ConfigManager {
    static [Config] LoadConfig([string]$ConfigPath) {
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found at $ConfigPath"
        }

        $configData = Import-PowerShellDataFile -Path $ConfigPath
        $config = [Config]::new()
        
        foreach ($property in $configData.Keys) {
            if ($config.PSObject.Properties.Name -contains $property) {
                $config.$property = $configData[$property]
            }
        }

        $config.Validate()
        return $config
    }
}

# Log extraction service
class LogExtractionService {
    hidden [Config]$Config
    hidden [FileUploadService]$UploadService
    hidden [hashtable]$ExtractionCommands
    hidden [hashtable]$LogTypeResults = @{}

    LogExtractionService([Config]$Config, [FileUploadService]$UploadService) {
        $this.Config = $Config
        $this.UploadService = $UploadService
        $this.InitializeExtractionCommands()
    }

    [void]InitializeExtractionCommands() {
        $this.ExtractionCommands = @{
            'UALStatistics' = { param($p) Get-UALStatistics @p }
            'UAL' = { param($p) Get-UALAll @p -Output $this.Config.LogFormats['UAL'] -Interval 1440 }
            'AdminAuditLogs' = { param($p) Get-AdminAuditLog -StartDate $p.StartDate -EndDate $p.EndDate -OutputDir $p.OutputDir }
            'MailboxAuditLogs' = { param($p) Get-MailboxAuditLog @p }
            'MessageTraceLogs' = { param($p) Get-MessageTraceLog @p }
            'OAuthPermissions' = { param($p) Get-OAuthPermissions -OutputDir $p.OutputDir }
            'MailboxRules' = { param($p) Get-MailboxRules -UserIds $p.UserIds -OutputDir $p.OutputDir }
            'TransportRules' = { param($p) Get-TransportRules -OutputDir $p.OutputDir }
            'Users' = { param($p) Get-Users -OutputDir $p.OutputDir }
            'AdminUsers' = { param($p) Get-AdminUsers -OutputDir $p.OutputDir }
            'MFA' = { param($p) Get-MFA -OutputDir $p.OutputDir }
            'RiskyUsers' = { param($p) Get-RiskyUsers -OutputDir $p.OutputDir -UserIds $p.UserIds }
            'RiskyDetections' = { param($p) Get-RiskyDetections -OutputDir $p.OutputDir -UserIds $p.UserIds }
            'ConditionalAccessPolicies' = { param($p) Get-ConditionalAccessPolicies -OutputDir $p.OutputDir }
            'ADSignInLogs' = { param($p) Get-ADSignInLogsGraph @p }
            'ADAuditLogs' = { param($p) Get-ADAuditLogsGraph @p }
            'AzureActivityLogs' = { param($p) Get-ActivityLogs -StartDate $p.StartDate -EndDate $p.EndDate -OutputDir $p.OutputDir  }
            'DirectoryActivityLogs' = { param($p) Get-DirectoryActivityLogs  -StartDate $p.StartDate -EndDate $p.EndDate -OutputDir $p.OutputDir  }
            'EmailSessions' = { param($p) 
                [Logger]::Write("Starting EmailSessions extraction for user: $($p.UserIds)", "INFO")
                
                # Create email directory
                $emailDir = Join-Path $p.OutputDir "Emails"
                if (-not (Test-Path $emailDir)) {
                    New-Item -ItemType Directory -Force -Path $emailDir | Out-Null
                    [Logger]::Write("Created email directory: $emailDir", "DEBUG")
                }
                
                # Step 1: Get sessions and upload the sessions file
                [Logger]::Write("Getting sessions for date range: $($p.StartDate) to $($p.EndDate)", "INFO")
                $sessions = Get-Sessions -StartDate $p.StartDate -EndDate $p.EndDate -UserIds $p.UserIds -Output "Yes" -OutputDir $p.OutputDir
                
                $sessionsFile = Join-Path $p.OutputDir "Sessions-$($p.UserIds).csv"
                if (Test-Path $sessionsFile) {
                    [Logger]::Write("Uploading sessions file to Observe", "INFO")
                    $this.UploadService.UploadFile($sessionsFile, "email_sessions")
                }
                
                # Step 2: For each unique session, get message IDs and upload the message IDs file
                [Logger]::Write("Loading sessions from CSV: $sessionsFile", "DEBUG")
                $uniqueSessions = Import-Csv $sessionsFile | 
                    Select-Object -Property SessionId -Unique | 
                    Where-Object { $_.SessionId }
                
                [Logger]::Write("Found $($uniqueSessions.Count) unique sessions", "INFO")

                foreach ($session in $uniqueSessions) {
                    [Logger]::Write("Processing session: $($session.SessionId)", "INFO")
                    
                    # Get message IDs for this session
                    [Logger]::Write("Getting message IDs for session: $($session.SessionId)", "DEBUG")
                    Get-MessageIDs -StartDate $p.StartDate -EndDate $p.EndDate -Sessions $session.SessionId -Output "Yes" -OutputDir $p.OutputDir

                    $messageIdsPath = "$($p.OutputDir)\MessageIDs-$($session.SessionId).csv"
                    if (Test-Path $messageIdsPath) {
                        [Logger]::Write("Uploading message IDs file to Observe", "INFO")
                        $this.UploadService.UploadFile($messageIdsPath, "email_message_ids")
                    }
                    
                    [Logger]::Write("Loading message IDs from: $messageIdsPath", "DEBUG")
                    
                    $messageIds = Import-Csv $messageIdsPath |
                        Select-Object -Property InternetMessageId -Unique |
                        Where-Object { $_.InternetMessageId }
                    
                    [Logger]::Write("Found $($messageIds.Count) unique messages for session", "INFO")

                    foreach ($msgId in $messageIds) {
                        [Logger]::Write("Processing message ID: $($msgId.InternetMessageId)", "DEBUG")
                        
                        try {
                            # Get email content
                            $emailContent = Show-Email -userIds $p.UserIds -internetMessageId $msgId.InternetMessageId
                            
                            if ($emailContent) {
                                # Create safe filename from message ID
                                $safeFileName = $msgId.InternetMessageId.TrimStart('<').TrimEnd('>').Trim() -replace '[:\\/*?""|]', '_'
                                $emailPath = Join-Path -Path $emailDir -ChildPath "$safeFileName.json"
                                
                                [Logger]::Write("Attempting to save email content to: $emailPath", "DEBUG")
                                
                                # Save email content as JSON and verify the file exists
                                $emailContent | ConvertTo-Json -Depth 10 | Set-Content -Path $emailPath -Encoding UTF8
                                
                                if (Test-Path $emailPath) {
                                    [Logger]::Write("Email content saved successfully at: $emailPath", "DEBUG")
                                    
                                    # Verify file size before upload
                                    $fileInfo = Get-Item $emailPath
                                    [Logger]::Write("File size: $($fileInfo.Length) bytes", "DEBUG")
                                    
                                    [Logger]::Write("Uploading email to observe...", "DEBUG")
                                    $this.UploadService.UploadFile($emailPath, "email_content")
                                    [Logger]::Write("Email uploaded successfully", "INFO")
                                } else {
                                    [Logger]::Write("Failed to save email content - file does not exist: $emailPath", "ERROR")
                                }
                            } else {
                                [Logger]::Write("No content returned from Show-Email for message ID: $($msgId.InternetMessageId)", "WARNING")
                            }
                        } catch {
                            [Logger]::Write("Error processing message ID $($msgId.InternetMessageId): $($_.Exception.Message)", "ERROR")
                            continue
                        }
                    }
                }
                
                [Logger]::Write("EmailSessions extraction completed", "INFO")
            }
        }
    }

    [bool]ExtractLogs([string]$LogType, [DateTime]$StartDate, [DateTime]$EndDate, [string[]]$EmailAddresses) {
        if (-not $this.ExtractionCommands.ContainsKey($LogType)) {
            [Logger]::Write("Unknown log type: $LogType", "ERROR")
            return $false
        }

        $outputDir = Join-Path $this.Config.TempDir $LogType
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

        $params = @{
            StartDate = $StartDate
            EndDate = $EndDate
            OutputDir = $outputDir
        }

        if ($EmailAddresses) {
            $params.UserIds = $EmailAddresses -join ","
        }

        $retryCount = 0
        $success = $false
        
        while ($retryCount -lt $this.Config.RetryAttempts) {
            try {
                & $this.ExtractionCommands[$LogType] $params
                
                # Skip file processing entirely for EmailSessions
                if ($LogType -eq "EmailSessions") {
                    $this.LogTypeResults[$LogType] = $true
                    $success = $true
                    break
                }
                
                # Process files for other log types
                $files = Get-ChildItem -Path $outputDir -Filter "*.$($this.Config.LogFormats[$LogType].ToLower())"
                foreach ($file in $files) {
                    if ($this.UploadService.UploadFile($file.FullName, $LogType)) {
                        $this.LogTypeResults[$LogType] = $true
                    }
                }
                
                $success = $true
                break
            }
            catch {
                $retryCount++
                [Logger]::Write("Error extracting $LogType logs (Attempt $retryCount of $($this.Config.RetryAttempts)): $($_.Exception.Message)", "ERROR")
                
                if ($retryCount -ge $this.Config.RetryAttempts) {
                    break
                }
                
                Start-Sleep -Seconds $this.Config.RetryDelaySeconds
            }
        }

        # Send notification if extraction succeeded but no data was uploaded
        if ($success -and -not $this.HasFilesForLogType($LogType)) {
            [Logger]::Write("No data found for $LogType, sending notification", "INFO")
            $this.UploadService.SendNoDataNotification($StartDate, $EndDate, $LogType)
        }

        return $success
    }

    [bool]HasFilesForLogType([string]$LogType) {
        return $this.LogTypeResults.ContainsKey($LogType) -and $this.LogTypeResults[$LogType]
    }
}

# File upload service
class FileUploadService {
    hidden [Config]$Config

    FileUploadService([Config]$Config) {
        $this.Config = $Config
    }

    [bool]UploadFile([string]$FilePath, [string]$LogType) {
        if ((Get-Item $FilePath).Length -eq 0) {
            Write-Error "File $FilePath is empty. Skipping upload."
            return $false
        }

        $retryCount = 0
        while ($retryCount -lt $this.Config.RetryAttempts) {
            try {
                $result = $this.ExecuteUpload($FilePath, $LogType)
                [Logger]::Write("Successfully uploaded $FilePath", "INFO")
                return $true
            }
            catch {
                $retryCount++
                $this.HandleUploadError($_, $FilePath, $retryCount)
                
                if ($retryCount -ge $this.Config.RetryAttempts) {
                    return $false
                }
                
                Start-Sleep -Seconds $this.Config.RetryDelaySeconds
            }
        }
        return $false
    }

    hidden [object]ExecuteUpload([string]$FilePath, [string]$LogType) {
        # Convert relative path to absolute path if needed
        if (-not [System.IO.Path]::IsPathRooted($FilePath)) {
            $FilePath = Join-Path (Get-Location).Path $FilePath
        }
        
        # Normalize path separators for current OS
        $FilePath = [System.IO.Path]::GetFullPath($FilePath).Replace([System.IO.Path]::AltDirectorySeparatorChar, [System.IO.Path]::DirectorySeparatorChar)
        
        [Logger]::Write("Attempting to upload file with normalized path: $FilePath", "DEBUG")
        
        # Verify file exists before attempting to read
        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "File not found: $FilePath"
        }
        
        $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
        $contentType = $this.GetContentType($extension)
        
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        $url = $this.BuildUploadUrl($FilePath, $LogType)
        $headers = @{
            "Authorization" = "Bearer $($this.Config.ObserveToken)"
            "Content-Type" = $contentType
        }

        return Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $fileBytes -ContentType $contentType
    }

    hidden [string]GetContentType([string]$extension) {
        return $(switch ($extension) {
            ".csv"  { "text/csv" }
            ".json" { "application/json" }
            default { "application/octet-stream" }
        })
    }

    hidden [string]BuildUploadUrl([string]$FilePath, [string]$LogType) {
        $baseUrl = "$($this.Config.ObserveEndpoint)/$LogType"
        $urlParams = $this.GetUrlParameters($FilePath)
        $queryString = ($urlParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '&'
        return "$baseUrl`?$queryString"
    }

    hidden [hashtable]GetUrlParameters([string]$FilePath) {
        $params = @{
            'filename' = [System.IO.Path]::GetFileName($FilePath)
            'format' = [System.IO.Path]::GetExtension($FilePath).TrimStart('.').ToLower()
            'timestamp' = [System.Web.HttpUtility]::UrlEncode((Get-Date).ToUniversalTime().ToString("o"))
            'start_date' = [System.Web.HttpUtility]::UrlEncode($script:StartDate.ToUniversalTime().ToString("o"))
            'end_date' = [System.Web.HttpUtility]::UrlEncode($script:EndDate.ToUniversalTime().ToString("o"))
        }

        if ($script:EmailAddresses) {
            $params['email_addresses'] = [System.Web.HttpUtility]::UrlEncode(($script:EmailAddresses -join ","))
        }

        return $params
    }

    hidden [void]HandleUploadError($error, [string]$FilePath, [int]$retryCount) {
        $errorDetails = @{
            Message = $error.Exception.Message
            Response = if ($error.Exception.Response) { 
                "Status: $($error.Exception.Response.StatusCode.value__) $($error.Exception.Response.StatusDescription)"
            } else { "No response details available" }
            InnerException = if ($error.Exception.InnerException) {
                $error.Exception.InnerException.Message
            } else { "No inner exception" }
        }
        
        [Logger]::Write("Failed to upload $FilePath (Attempt $retryCount of $($this.Config.RetryAttempts))", "ERROR")
        [Logger]::Write("Error details: $($errorDetails | ConvertTo-Json)", "DEBUG")
    }

    [bool]SendNoDataNotification([DateTime]$StartDate, [DateTime]$EndDate, [string]$LogType) {
        try {
            $body = @{
                message = "No data found for log type: $LogType"
                start_date = $StartDate.ToUniversalTime().ToString("o")
                end_date = $EndDate.ToUniversalTime().ToString("o")
                log_type = $LogType
            } | ConvertTo-Json

            $url = "$($this.Config.ObserveEndpoint)/notification"
            $headers = @{
                "Authorization" = "Bearer $($this.Config.ObserveToken)"
                "Content-Type" = "application/json"
            }

            Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
            [Logger]::Write("Sent no data notification for $LogType to Observe", "INFO")
            return $true
        }
        catch {
            [Logger]::Write("Failed to send no data notification for $LogType - $($_.Exception.Message)", "ERROR")
            return $false
        }
    }
}

# Main execution
try {
    # Get the script's directory
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        $scriptDir = (Get-Location).Path
    }
    
    [Logger]::Write("Script running from directory: $scriptDir", "DEBUG")
    
    # Update ConfigPath to use script directory if it's a relative path
    if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
        $ConfigPath = Join-Path $scriptDir $ConfigPath
    }
    
    $scriptStartTime = Get-Date
    [Logger]::Write("Starting script execution at $scriptStartTime", "DEBUG")
    
    [Logger]::Write("Loading configuration from $ConfigPath", "DEBUG")
    $config = [ConfigManager]::LoadConfig($ConfigPath)
    
    if (-not $config) {
        throw "Configuration failed to load"
    }
    
    [Logger]::Write("Creating upload service", "DEBUG")
    $uploadService = [FileUploadService]::new($config)
    
    [Logger]::Write("Creating extraction service", "DEBUG")
    $extractionService = [LogExtractionService]::new($config, $uploadService)

    # Get all log types from the ValidateSet attribute, excluding "All"
    $allLogTypes = (Get-Command $PSCommandPath -ErrorAction Stop).Parameters['LogTypes'].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
        Select-Object -ExpandProperty ValidValues |
        Where-Object { $_ -ne "All" }

    # If "All" is specified, use all available log types
    $logTypesToProcess = if ($LogTypes -contains "All") { $allLogTypes } else { $LogTypes }

    foreach ($logType in $logTypesToProcess) {
        $logTypeStartTime = Get-Date
        [Logger]::Write("Processing $logType logs...", "INFO")
        
        $extractionService.ExtractLogs($logType, $StartDate, $EndDate, $EmailAddresses)
        
        $logTypeEndTime = Get-Date
        $duration = $logTypeEndTime - $logTypeStartTime
        [Logger]::Write("Completed $logType logs processing in $($duration.TotalSeconds) seconds", "DEBUG")
    }
    
    $scriptEndTime = Get-Date
    $totalDuration = $scriptEndTime - $scriptStartTime
    [Logger]::Write("Script execution completed in $($totalDuration.TotalMinutes) minutes", "DEBUG")
}
catch {
    [Logger]::Write("Critical error: $($_.Exception.Message)", "ERROR")
    [Logger]::Write("Stack trace: $($_.ScriptStackTrace)", "DEBUG")
}
finally {
    if (Test-Path $config.TempDir) {
        Remove-Item $config.TempDir -Recurse -Force
    }
}
