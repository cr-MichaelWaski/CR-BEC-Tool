# CR-BEC-Tool

# Extract-M365Logs.ps1

`Extract-M365Logs.ps1` is a PowerShell script designed to extract various logs and data from Microsoft 365 services and upload them to a specified endpoint. The script is configurable and supports multiple log types, making it a versatile tool for administrators and security professionals.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Parameters](#parameters)
  - [Examples](#examples)
- [Log Types](#log-types)
- [Error Handling and Logging](#error-handling-and-logging)
- [Contributing](#contributing)
- [License](#license)

## Features

- Extract logs from various Microsoft 365 services, including:
  - Unified Audit Logs (UAL)
  - Admin Audit Logs
  - Mailbox Audit Logs
  - Azure AD Sign-In Logs
  - Azure AD Audit Logs
  - Conditional Access Policies
  - And more
- Supports extraction for specific email addresses
- Configurable retry mechanisms for robustness
- Modular design with classes for configuration, logging, extraction, and file uploading
- Sends notifications when no data is found for a log type

## Prerequisites

- PowerShell 5.1 or later
- Required PowerShell modules for Microsoft Graph and Exchange Online:
  - [Microsoft.Graph](https://www.powershellgallery.com/packages/Microsoft.Graph)
  - [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
- Connectivity to Microsoft 365 services
- Appropriate permissions to access the required logs and data
- An endpoint and token for data upload (configured in `config.psd1`)
- https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Prerequisites.html
- https://microsoft-365-extractor-suite.readthedocs.io/en/latest/installation/Installation.html

### Setting up Observe Integration

1. **Create Observe Datastream**
   - Navigate to Observe UI
   - Go to Datastreams > Create Datastream
   - Click Create
   - Note the datastream URL for configuration

2. **Create Observe Token**
   - Select your newly created datastream
   - Click Create > Token
   - Click Continue
   - Copy the generated token
   - Click Continue
   - Save this token for use in `config.psd1`

### Azure AD Application Registration

1. **Register Application in Azure AD**
   - Sign in to the [Azure Portal](https://portal.azure.com)
   - Navigate to Azure Active Directory > App registrations
   - Click "New registration"
   - Name your application
   - Select supported account types
   - Click Register
   - Note the Application (client) ID and Directory (tenant) ID

2. **Configure API Permissions**
   - In your registered application
   - Go to API permissions
   - Click "Add a permission"
   - Select Microsoft Graph
   - Add the following permissions:
     - User.Read.All
     - Directory.Read.All
     - AuditLog.Read.All
     - Mail.Read
     - Mail.ReadBasic
     - MailboxSettings.Read

3. **Create Client Secret**
   - Go to Certificates & secrets
   - Click "New client secret"
   - Add a description and select expiry
   - Copy and securely store the generated secret value

### Setting up Service Account Permissions

For investigations requiring audit log access, follow these steps to set up a service account with appropriate permissions:

1. **Create Service Account**
   - Go to Microsoft 365 admin center (admin.microsoft.com)
   - Navigate to Users > Active users
   - Click "Add a user"
   - Fill in the required information
   - Save the credentials securely

2. **Assign Global Reader Role**
   - In Microsoft 365 admin center
   - Go to Users > Active users
   - Select the newly created user
   - Click "Manage roles"
   - Add "Global Reader" role
   - Save changes

3. **Configure Exchange Audit Log Access**
   - Go to Exchange admin center
   - Navigate to Roles
   - Click "+" to create a new role group
   - Name the role group (e.g., "Audit Log Viewers")
   - Add the following roles:
     - "Audit"
     - "View-Only Audit Logs"
   - Add the service account as a member
   - Save the role group

4. **Verify Permissions**
   - Log in with the service account
   - Attempt to access audit logs
   - Verify you can view but not modify audit data
   - Test access to required Microsoft Graph endpoints

**Note**: Always follow the principle of least privilege when assigning permissions. The above permissions are typically sufficient for log extraction purposes while maintaining security.


## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/yourrepository.git
   ```

2. **Navigate to the Script Directory**

   ```bash
   cd yourrepository/src
   ```

3. **Install Required PowerShell Modules**

   ```powershell
   Install-Module -Name Microsoft.Graph -Scope CurrentUser
   Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser
   ```

## Configuration

Before running the script, you need to configure it using the `config.psd1` file.

### `config.psd1`

This file contains settings that the script uses to perform operations.

```powershell
@{
    ObserveEndpoint = "https://your-observe-endpoint.com/v1/http"
    ObserveToken = "your-observe-token"
    TempDir = "./ExtractorTemp"
    RetryAttempts = 3
    RetryDelaySeconds = 5
    LogFormats = @{
        AzureActivityLogs          = "JSON"
        DirectoryActivityLogs      = "CSV"
        UAL                        = "CSV"
        UALStatistics              = "CSV"
        MessageTraceLogs           = "CSV"
        MailboxAuditLogs           = "CSV"
        AdminAuditLogs             = "CSV"
        MailboxRules               = "CSV"
        TransportRules             = "CSV"
        Users                      = "CSV"
        AdminUsers                 = "CSV"
        MFA                        = "CSV"
        RiskyUsers                 = "CSV"
        RiskyDetections            = "CSV"
        ConditionalAccessPolicies  = "CSV"
        ADSignInLogs               = "JSON"
        ADAuditLogs                = "JSON"
        EmailSessions              = "CSV"
    }
} 
```

#### Configuration Parameters

- `ObserveEndpoint`: The endpoint URL where the extracted data will be uploaded.
- `ObserveToken`: The authorization token for the upload endpoint.
- `TempDir`: Temporary directory used by the script to store extracted data before uploading.
- `RetryAttempts`: Number of times the script will retry an operation before failing.
- `RetryDelaySeconds`: Delay between retries in seconds.
- `LogFormats`: A hashtable defining the expected file format for each log type.

#### Steps to Configure

1. Open `config.psd1` in a text editor.
2. Replace `"https://your-observe-endpoint.com/v1/http"` with your actual observe endpoint URL.
3. Replace `"your-observe-token"` with your actual observe token.
4. Adjust `RetryAttempts` and `RetryDelaySeconds` if needed.
5. Save the file.

## Usage

Run the script using PowerShell with the required parameters.

### Parameters

- `-StartDate` **(Mandatory)**: The start date for log extraction. Must be a `DateTime` object.
- `-EndDate` *(Optional)*: The end date for log extraction. Defaults to the current date and time.
- `-EmailAddresses` *(Optional)*: An array of email addresses to target specific users.
- `-ConfigPath` *(Optional)*: Path to the configuration file (`config.psd1`). Defaults to `.\\config.psd1`.
- `-LogTypes` *(Optional)*: An array of log types to extract. Defaults to `All`. Supported types:
  - `All`, `Users`, `AdminUsers`, `MFA`, `RiskyUsers`, `RiskyDetections`, `ConditionalAccessPolicies`, `OAuthPermissions`, `ADSignInLogs`, `ADAuditLogs`, `MailboxRules`, `TransportRules`, `AdminAuditLogs`, `MailboxAuditLogs`, `MessageTraceLogs`, `AzureActivityLogs`, `DirectoryActivityLogs`, `UALStatistics`, `UAL`, `EmailSessions`
- `-EnableDebug` *(Optional)*: Switch to enable debug logging.

### Examples

1. **Extract All Logs Between Two Dates**

   ```powershell
   .\Extract-M365Logs.ps1 -StartDate "2024-11-01" -EndDate "2024-11-29"
   ```

2. **Extract Only Azure Activity Logs**

   ```powershell
   .\Extract-M365Logs.ps1 -StartDate "2024-11-01" -LogTypes "AzureActivityLogs"
   ```

3. **Extract Logs for Specific Email Addresses**

   ```powershell
   .\Extract-M365Logs.ps1 -StartDate "2024-11-01" -EmailAddresses "user1@domain.com"
   ```

4. **Use a Custom Configuration File**

   ```powershell
   .\Extract-M365Logs.ps1 -StartDate "2024-11-01" -ConfigPath ".\custom_config.psd1"
   ```

5. **Enable Debug Logging**

   ```powershell
   .\Extract-M365Logs.ps1 -StartDate "2024-11-01" -EnableDebug
   ```

## Log Types

The script supports the following log types:

- **Users**: Retrieves user information.
- **AdminUsers**: Retrieves administrator user information.
- **MFA**: Retrieves Multi-Factor Authentication status and details.
- **RiskyUsers**: Retrieves information about users flagged as risky.
- **RiskyDetections**: Retrieves risky sign-in detections.
- **ConditionalAccessPolicies**: Retrieves conditional access policies.
- **OAuthPermissions**: Retrieves OAuth application permissions.
- **ADSignInLogs**: Retrieves Azure AD sign-in logs.
- **ADAuditLogs**: Retrieves Azure AD audit logs.
- **MailboxRules**: Retrieves mailbox rules.
- **TransportRules**: Retrieves transport rules.
- **AdminAuditLogs**: Retrieves admin audit logs.
- **MailboxAuditLogs**: Retrieves mailbox audit logs.
- **MessageTraceLogs**: Retrieves message trace logs.
- **AzureActivityLogs**: Retrieves Azure activity logs.
- **DirectoryActivityLogs**: Retrieves directory activity logs.
- **UALStatistics**: Retrieves Unified Audit Log statistics.
- **UAL**: Retrieves Unified Audit Logs.
- **EmailSessions**: Retrieves email session information and content.

## Error Handling and Logging

The script includes robust error handling and logging mechanisms.

- **Logging**: Uses a custom `Logger` class to write logs with timestamps and log levels.
- **Error Handling**: Implements try-catch blocks to handle exceptions and retries operations based on the configured retry attempts and delay.
- **Notifications**: Sends a notification to the observe endpoint when no data is found for a specific log type.

**Log Levels**:

- `INFO`: General information about the script's execution.
- `DEBUG`: Detailed information useful for debugging (enabled with `-EnableDebug`).
- `WARNING`: Warnings about potential issues.
- `ERROR`: Errors that occur during execution.
