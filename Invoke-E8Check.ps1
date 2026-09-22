<#
.SYNOPSIS
    Checks the local Windows machine against selected ACSC Essential Eight
    Maturity Level One indicators.

.DESCRIPTION
    Read-only indicator check. This script makes NO changes to system settings.
    It is not a formal Essential Eight maturity assessment.

.PARAMETER OutputPath
    Folder where CSV and HTML reports are saved. Defaults to .\reports

.EXAMPLE
    .\Invoke-E8Check.ps1

.NOTES
    Author: Zachary Manning
    Only run on systems you own or are explicitly authorised to assess.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'reports')
)

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Result collection
# ---------------------------------------------------------------------------

# A List is more efficient than an array when adding items one at a time
$Results = [System.Collections.Generic.List[object]]::new()

function New-CheckResult {
    <#
    .SYNOPSIS
        Creates a standard result object for a single check.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Control,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Manual', 'Error')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Finding,

        [string]$Remediation = ''
    )

    [PSCustomObject]@{
        Control     = $Control
        Status      = $Status
        Finding     = $Finding
        Remediation = $Remediation
    }
}

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

function Test-ApplicationControl {
    <#
    .SYNOPSIS
        E8 Control 1: Checks whether an App Control for Business (WDAC)
        or AppLocker policy is enforced for user-mode applications.
    #>

    $control = 'Application control'
    $details = [System.Collections.Generic.List[string]]::new()

    # --- App Control for Business (WDAC) ---
    # We check the USER-MODE status. The kernel-mode status is often
    # "Enforced" on Windows 11 because of the default driver blocklist,
    # which does not control the applications users run.
    # Status codes: 0 = Off, 1 = Audit mode, 2 = Enforced
    $wdacUserMode = $null
    try {
        $cimParams = @{
            Namespace   = 'root\Microsoft\Windows\DeviceGuard'
            ClassName   = 'Win32_DeviceGuard'
            ErrorAction = 'Stop'
        }
        $deviceGuard  = Get-CimInstance @cimParams
        $wdacUserMode = $deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
        $details.Add("WDAC user-mode status: $wdacUserMode (0=Off, 1=Audit, 2=Enforced)")
    }
    catch {
        $details.Add("WDAC status could not be read: $($_.Exception.Message)")
    }

    # --- AppLocker ---
    # A rule collection counts only if it contains rules. AppLocker also
    # needs the Application Identity service running to enforce anything.
    $appLockerMode = 'Not configured'
    try {
        $policy      = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $collections = @($policy.RuleCollections | Where-Object { $_.Count -gt 0 })

        if ($collections | Where-Object { $_.EnforcementMode -eq 'Enabled' }) {
            $appLockerMode = 'Enforced'
        }
        elseif ($collections | Where-Object { $_.EnforcementMode -eq 'AuditOnly' }) {
            $appLockerMode = 'Audit only'
        }

        $appIdSvc = Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue
        $svcState = if ($appIdSvc) { $appIdSvc.Status } else { 'Not found' }

        if ($appLockerMode -eq 'Enforced' -and $svcState -ne 'Running') {
            $appLockerMode = 'Rules exist but AppIDSvc not running'
        }

        $details.Add("AppLocker: $appLockerMode (AppIDSvc: $svcState)")
    }
    catch {
        $details.Add("AppLocker status could not be read: $($_.Exception.Message)")
    }

    # --- Decide the result ---
    $finding     = $details -join '; '
    $remediation = 'Deploy an App Control for Business (WDAC) or AppLocker policy in ' +
                   'enforced mode that limits execution to an approved set, including ' +
                   'user profile and temp folders. Test in audit mode first. Note: ' +
                   'Windows Home cannot enforce AppLocker.'

    if ($wdacUserMode -eq 2 -or $appLockerMode -eq 'Enforced') {
        New-CheckResult -Control $control -Status 'Pass' -Finding $finding
    }
    elseif ($wdacUserMode -eq 1 -or $appLockerMode -eq 'Audit only') {
        New-CheckResult -Control $control -Status 'Warning' -Finding $finding -Remediation $remediation
    }
    else {
        New-CheckResult -Control $control -Status 'Fail' -Finding $finding -Remediation $remediation
    }
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

Write-Host 'Essential Eight ML1 Indicator Check' -ForegroundColor Cyan
Write-Host "Read-only. Run only on systems you own or are authorised to assess.`n" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

$Results.Add((Test-ApplicationControl))

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$Results | Format-Table -AutoSize