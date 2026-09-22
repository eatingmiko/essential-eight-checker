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
# Banner
# ---------------------------------------------------------------------------

Write-Host 'Essential Eight ML1 Indicator Check' -ForegroundColor Cyan
Write-Host "Read-only. Run only on systems you own or are authorised to assess.`n" -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

# Temporary test result - we'll replace this with real checks
$Results.Add((New-CheckResult -Control 'Test' -Status 'Pass' -Finding 'Skeleton runs correctly'))

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$Results | Format-Table -AutoSize