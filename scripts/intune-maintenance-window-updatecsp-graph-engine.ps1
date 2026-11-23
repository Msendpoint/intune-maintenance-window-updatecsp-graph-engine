### FILE: src/IntuneMaintenanceWindow.ps1
#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
Creates and assigns an Intune Windows custom configuration profile that enforces Windows Update maintenance windows (Update CSP).

.DESCRIPTION
This script uses Microsoft Graph to create a Device Configuration profile (windows10CustomConfiguration) with OMA-URI settings under
./Device/Vendor/MSFT/Policy/Config/Update/* for Windows Update maintenance windows.

It includes retry logic for common transient Graph throttling (429) and fails fast on duplicate-name conflicts (409).
After creation, it assigns the profile to the specified Entra (Azure AD) device group.

It can optionally validate the effective values on the endpoint by reading PolicyManager registry keys.

.EXAMPLE
# Create and assign a weekly Saturday maintenance window (01:00-05:00) to the target device group
.
.
# Run interactively (will prompt for Graph auth unless already authenticated in the environment)
# TenantGroupId is the Entra device group object id
$groupId = '00000000-0000-0000-0000-000000000000'
.
./src/IntuneMaintenanceWindow.ps1 -TenantGroupId $groupId -ProfileName 'WU - Maintenance Window - Weekly Sat 01:00-05:00' -StartDate '2026-11-28' -StartTime '01:00' -DurationHours 4 -RepeatScheduleOption 2 -UpdateActions 1

.NOTES
Author:      Souhaiel Morhag
Company:     MSEndpoint.com
Blog:        https://msendpoint.com
Academy:     https://app.msendpoint.com/academy
LinkedIn:    https://linkedin.com/in/souhaiel-morhag
GitHub:      https://github.com/Msendpoint
License:     MIT
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantGroupId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ProfileName = 'WU - Maintenance Window - Weekly Sat 01:00-05:00',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$StartDate = '2026-11-28',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [string]$StartTime = '01:00',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 168)]
    [int]$DurationHours = 4,

    # Validate these values against your target Windows build
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 6)]
    [int]$RepeatScheduleOption = 2,

    # Example mapping from the article: 1
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 10)]
    [int]$UpdateActions = 1,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateOnEndpoint,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIfGraph
)

function Invoke-GraphWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        try {
            $attempt++
            return & $ScriptBlock
        }
        catch {
            $err = $_
            $message = $err.Exception.Message

            if ($message -match '429' -or $message -match 'Too Many Requests') {
                $sleep = [Math]::Min(60, 5 * $attempt)
                Write-Warning "Graph throttled (429). Retrying in $sleep seconds... Attempt $attempt/$MaxRetries."
                if ($attempt -ge $MaxRetries) { throw }
                Start-Sleep -Seconds $sleep
                continue
            }

            if ($message -match '409' -or $message -match 'Conflict') {
                throw "Graph conflict (409). A profile with the same name may already exist. ProfileName='$ProfileName'"
            }

            throw
        }

        if ($attempt -ge $MaxRetries) {
            throw "Graph request failed after $MaxRetries attempts."
        }
    }
}

function Get-ExistingDeviceConfigByDisplayName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    # Escape single quotes for OData filter
    $escaped = $DisplayName.Replace("'", "''")

    $existing = Invoke-GraphWithRetry -ScriptBlock {
        Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?`$filter=displayName eq '$escaped'"
    }

    return $existing.value
}

function Build-OmaSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DurationHours,

        [Parameter(Mandatory = $true)]
        [string]$StartDate,

        [Parameter(Mandatory = $true)]
        [string]$StartTime,

        [Parameter(Mandatory = $true)]
        [int]$RepeatScheduleOption,

        [Parameter(Mandatory = $true)]
        [int]$UpdateActions
    )

    return @(
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowEnabled'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowEnabled'
            value         = 1
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowDurationHours'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowDurationHours'
            value         = $DurationHours
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingString'
            displayName   = 'MaintenanceWindowStartDate'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowStartDate'
            value         = $StartDate
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingString'
            displayName   = 'MaintenanceWindowStartTime'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowStartTime'
            value         = $StartTime
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowRepeatScheduleOption'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowRepeatScheduleOption'
            value         = $RepeatScheduleOption
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowWeeklySaturday'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowWeeklySaturday'
            value         = 1
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowWeeklyInterval'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowWeeklyInterval'
            value         = 1
        },
        @{
            '@odata.type' = '#microsoft.graph.omaSettingInteger'
            displayName   = 'MaintenanceWindowUpdateActions'
            omaUri        = './Device/Vendor/MSFT/Policy/Config/Update/MaintenanceWindowUpdateActions'
            value         = $UpdateActions
        }
    )
}

function Validate-PolicyManagerOnEndpoint {
    [CmdletBinding()]
    param()

    try {
        $path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
        if (-not (Test-Path $path)) {
            Write-Warning "PolicyManager registry path not found: $path"
            return
        }

        $props = Get-ItemProperty -Path $path -ErrorAction Stop | Select-Object MaintenanceWindow*
        if ($null -eq $props) {
            Write-Warning 'No MaintenanceWindow* properties found.'
            return
        }

        Write-Host 'Effective MaintenanceWindow* values from PolicyManager:'
        $props | Format-List *
    }
    catch {
        Write-Warning "Validation failed: $($_.Exception.Message)"
    }
}

try {
    # Graph connection. Prefer existing session if caller already connected.
    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'Microsoft Graph PowerShell SDK is not installed or not available in the session.'
    }

    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $ctx -or -not $ctx.Account) {
        Write-Verbose 'No Graph context detected. Connecting with required scopes...'
        if ($WhatIfGraph) {
            # If WhatIfGraph, still connect to validate auth flow? We keep it simple: do not attempt.
        } else {
            Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All' -NoWelcome | Out-Null
        }
    }

    $existing = $null
    if (-not $WhatIfGraph) {
        $existing = Get-ExistingDeviceConfigByDisplayName -DisplayName $ProfileName
    }

    if (-not $WhatIfGraph) {
        if ($existing -and $existing.Count -gt 0) {
            throw "A device configuration named '$ProfileName' already exists. Use a unique name or implement PATCH logic."
        }
    }

    $omaSettings = Build-OmaSettings -DurationHours $DurationHours -StartDate $StartDate -StartTime $StartTime -RepeatScheduleOption $RepeatScheduleOption -UpdateActions $UpdateActions

    $body = [ordered]@{
        '@odata.type' = '#microsoft.graph.windows10CustomConfiguration'
        displayName   = $ProfileName
        description   = 'Constrains Windows update actions to a scheduled maintenance window.'
        omaSettings   = $omaSettings
    } | ConvertTo-Json -Depth 10

    if ($WhatIfGraph) {
        Write-Host 'WhatIfGraph: would create and assign the following Intune device configuration:'
        Write-Output $body
        exit 0
    }

    if ($PSCmdlet.ShouldProcess("Intune device configuration '$ProfileName'", 'Create')) {
        $created = Invoke-GraphWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations' -Body $body -ContentType 'application/json'
        }

        if (-not $created.id) {
            throw 'Profile creation returned no ID.'
        }

        $assignBody = @{
            assignments = @(
                @{
                    target = @{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId       = $TenantGroupId
                    }
                }
            )
        } | ConvertTo-Json -Depth 6

        Invoke-GraphWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($created.id)/assign" -Body $assignBody -ContentType 'application/json'
        }