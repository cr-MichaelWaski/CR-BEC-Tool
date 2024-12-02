#These will pop up web based logins
Connect-M365
Connect-AzureAZ

# This is for authenticating the registered application
# Define the Application (Client) ID and Secret
$ApplicationClientId = 'APPLICATION_ID_HERE' # Application (Client) ID
$ApplicationClientSecret = 'SECRET_HERE' # Application Secret Value
$TenantId = 'TENANT_ID_HERE' # Tenant ID

# Convert the Client Secret to a Secure String
$SecureClientSecret = ConvertTo-SecureString -String $ApplicationClientSecret -AsPlainText -Force

# Create a PSCredential Object Using the Client ID and Secure Client Secret
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationClientId, $SecureClientSecret
# Connect to Microsoft Graph Using the Tenant ID and Client Secret Credential
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential
