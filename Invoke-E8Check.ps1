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
        [ValidateSet('Pass', 'Fail', 'Warning', 'Manual', 'Error', 'N/A')]
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

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Returns a registry value, or $null if the key or value does not exist.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
    }
    catch {
        $null
    }
}

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

function Test-ApplicationControl {
    <#
    .SYNOPSIS
        E8 Control 1: Checks whether an organisation-controlled application
        control policy (App Control for Business / WDAC or AppLocker) is enforced.
    #>

    $control = 'Application control'
    $details = [System.Collections.Generic.List[string]]::new()

    # --- App Control for Business (WDAC), user-mode ---
    # Kernel-mode status is ignored: on Windows 11 it is usually "Enforced"
    # by the default vulnerable driver blocklist, which does not control apps.
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

    # --- Smart App Control ---
    # Built on the WDAC engine, so it sets user-mode status to Enforced.
    # It is reputation-based (Microsoft decides what is trusted), not an
    # organisation-approved allow-list, so it does not meet the ML1 intent.
    # Values: 0 = Off, 1 = On, 2 = Evaluation
    $sacParams = @{
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        Name = 'VerifiedAndReputablePolicyState'
    }
    $sacState = Get-RegistryValue @sacParams
    $sacText  = switch ($sacState) {
        0       { 'Off' }
        1       { 'On' }
        2       { 'Evaluation' }
        default { 'Not present' }
    }
    $details.Add("Smart App Control: $sacText")

    # --- AppLocker ---
    # The AppLocker module does not exist on Windows Home, so check for the
    # cmdlet first instead of letting the call fail.
    $appLockerMode = 'Not configured'
    if (Get-Command -Name 'Get-AppLockerPolicy' -ErrorAction SilentlyContinue) {
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
    }
    else {
        $details.Add('AppLocker: module not available on this edition (e.g. Windows Home)')
    }

    # --- Decide the result ---
    $finding     = $details -join '; '
    $remediation = 'Deploy an organisation-managed App Control for Business (WDAC) or ' +
                   'AppLocker policy in enforced mode that limits execution to an ' +
                   'approved set, including user profile and temp folders. ' +
                   'Requires Windows Pro/Enterprise with central management.'

    if ($appLockerMode -eq 'Enforced') {
        New-CheckResult -Control $control -Status 'Pass' -Finding $finding
    }
    elseif ($wdacUserMode -eq 2 -and $sacState -ne 1) {
        # Enforced WDAC that is not coming from Smart App Control
        New-CheckResult -Control $control -Status 'Pass' -Finding $finding
    }
    elseif ($wdacUserMode -eq 2 -and $sacState -eq 1) {
        # Limitation: if an org policy AND Smart App Control are both active,
        # this class can't tell them apart, so we report conservatively.
        $finding += '. Enforcement comes from Smart App Control (reputation-based), ' +
                    'not an organisation-approved allow-list.'
        New-CheckResult -Control $control -Status 'Warning' -Finding $finding -Remediation $remediation
    }
    elseif ($wdacUserMode -eq 1 -or $appLockerMode -eq 'Audit only') {
        New-CheckResult -Control $control -Status 'Warning' -Finding $finding -Remediation $remediation
    }
    else {
        New-CheckResult -Control $control -Status 'Fail' -Finding $finding -Remediation $remediation
    }
}

function Test-OSPatching {
    <#
    .SYNOPSIS
        E8 Control 6: Checks the install date of the most recent Windows update.
    #>
    param(
        [int]$MaxAgeDays = 30
    )

    $control     = 'Patch operating systems'
    $remediation = 'Run Windows Update and install all available updates. ' +
                   'ML1: workstation OS patches within one month of release ' +
                   '(internet-facing: two weeks, or 48 hours if an exploit exists).'

    try {
        $latest = Get-HotFix -ErrorAction Stop |
            Where-Object { $_.InstalledOn } |
            Sort-Object -Property InstalledOn -Descending |
            Select-Object -First 1

        if (-not $latest) {
            return New-CheckResult -Control $control -Status 'Warning' `
                -Finding 'No updates with an install date were found.' `
                -Remediation 'Verify patch status manually in Settings > Windows Update > Update history.'
        }

        $ageDays = [int]((Get-Date) - $latest.InstalledOn).TotalDays
        $finding = "Most recent update: $($latest.HotFixID), installed " +
                   "$($latest.InstalledOn.ToString('yyyy-MM-dd')) ($ageDays days ago)"

        if ($ageDays -le $MaxAgeDays) {
            New-CheckResult -Control $control -Status 'Pass' -Finding $finding
        }
        else {
            New-CheckResult -Control $control -Status 'Fail' -Finding $finding -Remediation $remediation
        }
    }
    catch {
        New-CheckResult -Control $control -Status 'Error' -Finding "Could not read update history: $($_.Exception.Message)"
    }
}

function Test-OfficeMacroSettings {
    <#
    .SYNOPSIS
        E8 Control 3: Checks Office macro settings enforced by policy.
    #>

    $control = 'Office macro settings'

    # Only Click-to-Run (Microsoft 365 / retail) Office is detected here
    $c2rPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if (-not (Test-Path -Path $c2rPath)) {
        return New-CheckResult -Control $control -Status 'N/A' `
            -Finding 'Click-to-Run Microsoft Office not detected.'
    }

    $policyRoot = 'HKCU:\Software\Policies\Microsoft\Office\16.0'
    $apps       = @('Word', 'Excel', 'PowerPoint')
    $issues     = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $apps) {
        $securityKey   = "$policyRoot\$app\Security"
        $blockInternet = Get-RegistryValue -Path $securityKey -Name 'blockcontentexecutionfrominternet'
        $vbaWarnings   = Get-RegistryValue -Path $securityKey -Name 'vbawarnings'

        if ($blockInternet -ne 1) {
            $issues.Add("${app}: internet macro blocking not enforced")
        }
        if ($vbaWarnings -notin @(3, 4)) {
            $value = if ($null -eq $vbaWarnings) { 'not set' } else { $vbaWarnings }
            $issues.Add("${app}: macros not disabled by policy (vbawarnings = $value)")
        }
    }

    $scanScope = Get-RegistryValue -Path "$policyRoot\Common\Security" -Name 'macroruntimescanscope'
    if ($scanScope -eq 0) {
        $issues.Add('Macro antivirus scanning disabled by policy')
    }

    $remediation = 'Use Group Policy or Intune to block macros from the internet, ' +
                   'disable macros for users without a business need (vbawarnings 4), ' +
                   'keep macro AV scanning on, and prevent users changing these settings.'

    if ($issues.Count -eq 0) {
        New-CheckResult -Control $control -Status 'Pass' `
            -Finding 'Macro policies enforced for Word, Excel and PowerPoint.'
    }
    else {
        New-CheckResult -Control $control -Status 'Fail' `
            -Finding ($issues -join '; ') -Remediation $remediation
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
$Results.Add((Test-OSPatching))
$Results.Add((Test-OfficeMacroSettings))

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$Results | Format-Table -AutoSize