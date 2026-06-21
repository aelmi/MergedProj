#requires -Version 5.1
<#
.SYNOPSIS
    For a SQL Server instance/alias, finds every Windows (AD) group that has a
    login, expands its members recursively (including nested groups), and reports
    each member's last logon date.

.DESCRIPTION
    Self-contained: uses System.Data.SqlClient (no dbatools) and .NET
    DirectoryServices (no ActiveDirectory/RSAT module). Must run on a domain-joined
    machine as a user who can read AD.

    Last logon:
      * Default  -> 'lastLogonTimestamp' (replicated, but lags up to ~14 days).
      * -Accurate -> queries every domain controller for 'lastLogon' and takes the
                     newest value (exact, but slower).

.PARAMETER SqlInstance
    SQL Server instance or client alias, e.g. 'PT-W16-SQL01' or 'PT-W22-SQL01\INST2'.

.PARAMETER SqlCredential
    Optional SQL login (for Linux/workgroup boxes). Omit for Windows auth.

.PARAMETER Accurate
    Query all DCs for the exact lastLogon instead of the imprecise replicated value.

.EXAMPLE
    .\Get-SqlAdGroupMemberLastLogon.ps1 -SqlInstance PT-W16-SQL01 | Format-Table -AutoSize

.EXAMPLE
    .\Get-SqlAdGroupMemberLastLogon.ps1 -SqlInstance PT-W16-SQL01 -Accurate |
        Export-Csv .\group_members.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [string]$SqlInstance,
    [pscredential]$SqlCredential,
    [switch]$Accurate
)

# ---------------------------------------------------------------------------
function Invoke-SqlQuery {
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [Parameter(Mandatory)][string]$Query,
        [string]$Database = 'master',
        [pscredential]$SqlCredential,
        [int]$ConnectTimeout = 8
    )
    $auth = if ($SqlCredential) {
        "User Id=$($SqlCredential.UserName);Password=$($SqlCredential.GetNetworkCredential().Password)"
    } else {
        'Integrated Security=SSPI'
    }
    $cs = "Server=$SqlInstance;Database=$Database;$auth;Encrypt=False;TrustServerCertificate=True;Connect Timeout=$ConnectTimeout;Application Name=AdGroupAudit"
    $cn = New-Object System.Data.SqlClient.SqlConnection $cs
    $cn.Open()
    try {
        $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query
        $dt  = New-Object System.Data.DataTable
        [void](New-Object System.Data.SqlClient.SqlDataAdapter $cmd).Fill($dt)
        , $dt
    } finally { $cn.Close() }
}

function Get-SqlWindowsGroup {
    # Returns DOMAIN\Group names that are Windows-group logins on the instance.
    param([Parameter(Mandatory)][string]$SqlInstance, [pscredential]$SqlCredential)
    $q = @"
SELECT name
FROM sys.server_principals
WHERE type = 'G'                       -- Windows group
  AND name LIKE '%\%'                  -- DOMAIN\Group form
  AND name NOT LIKE 'NT SERVICE\%'
  AND name NOT LIKE 'NT AUTHORITY\%'
  AND name NOT LIKE 'BUILTIN\%'
  AND name NOT LIKE '##%'
ORDER BY name
"@
    (Invoke-SqlQuery -SqlInstance $SqlInstance -Query $q -SqlCredential $SqlCredential).Rows |
        ForEach-Object { [string]$_.name }
}

function Resolve-AdGroup {
    # Bind to the group via its SID (works across domains) and return its DN.
    param([Parameter(Mandatory)][string]$NtName)
    $sid = ([System.Security.Principal.NTAccount]$NtName).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $de  = [ADSI]"LDAP://<SID=$sid>"
    $dn  = [string]$de.distinguishedName
    if (-not $dn) { throw "Could not bind to group '$NtName' in AD." }
    [pscustomobject]@{ NtName = $NtName; Dn = $dn; Sid = $sid }
}

function Get-AdGroupMemberRecursive {
    # All USER members of the group, nested groups flattened via the
    # LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) operator.
    param([Parameter(Mandatory)][string]$GroupDn)

    # Search within the group's own domain (DC= components of its DN)
    $dc   = ($GroupDn -split ',' | Where-Object { $_ -match '^DC=' }) -join ','
    $base = [ADSI]"LDAP://$dc"

    $ds = New-Object System.DirectoryServices.DirectorySearcher($base)
    $ds.Filter   = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$GroupDn))"
    $ds.PageSize = 1000
    'sAMAccountName','displayName','userAccountControl','lastLogonTimestamp','distinguishedName','mail' |
        ForEach-Object { [void]$ds.PropertiesToLoad.Add($_) }

    $results = $ds.FindAll()
    try {
        foreach ($r in $results) {
            $p   = $r.Properties
            $uac = if ($p['useraccountcontrol'].Count) { [int]$p['useraccountcontrol'][0] } else { 0 }
            $llt = if ($p['lastlogontimestamp'].Count) { [int64]$p['lastlogontimestamp'][0] } else { 0 }
            [pscustomobject]@{
                SamAccountName    = [string]$p['samaccountname'][0]
                DisplayName       = if ($p['displayname'].Count) { [string]$p['displayname'][0] } else { '' }
                Email             = if ($p['mail'].Count) { [string]$p['mail'][0] } else { '' }
                Enabled           = -not [bool]($uac -band 2)        # 0x2 = ACCOUNTDISABLE
                LastLogonDate     = if ($llt -gt 0) { [DateTime]::FromFileTimeUtc($llt).ToLocalTime() } else { $null }
                DistinguishedName = [string]$p['distinguishedname'][0]
            }
        }
    } finally { $results.Dispose() }
}

function Get-AdAccurateLastLogon {
    # Exact last logon = newest 'lastLogon' (non-replicated) across all DCs.
    param([Parameter(Mandatory)][string]$SamAccountName)
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $max = 0L
    foreach ($dcSrv in $domain.DomainControllers) {
        try {
            $ds = New-Object System.DirectoryServices.DirectorySearcher
            $ds.SearchRoot = [ADSI]"LDAP://$($dcSrv.Name)"
            $ds.Filter = "(sAMAccountName=$SamAccountName)"
            [void]$ds.PropertiesToLoad.Add('lastLogon')
            $r = $ds.FindOne()
            if ($r -and $r.Properties['lastlogon'].Count) {
                $v = [int64]$r.Properties['lastlogon'][0]
                if ($v -gt $max) { $max = $v }
            }
        } catch { }
    }
    if ($max -gt 0) { [DateTime]::FromFileTimeUtc($max).ToLocalTime() } else { $null }
}

function Get-SqlAdGroupMemberLastLogon {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SqlInstance,
        [pscredential]$SqlCredential,
        [switch]$Accurate
    )
    $groups = @(Get-SqlWindowsGroup -SqlInstance $SqlInstance -SqlCredential $SqlCredential)
    if (-not $groups) { Write-Warning "No Windows-group logins found on '$SqlInstance'."; return }
    Write-Verbose "Found $($groups.Count) Windows-group login(s) on $SqlInstance."

    $out = New-Object System.Collections.Generic.List[psobject]
    $gi = 0
    foreach ($g in $groups) {
        $gi++
        Write-Progress -Activity "Expanding AD groups on $SqlInstance" -Status "$g ($gi of $($groups.Count))" -PercentComplete ($gi / $groups.Count * 100)

        try { $grp = Resolve-AdGroup -NtName $g }
        catch {
            $out.Add([pscustomobject]@{ SqlInstance=$SqlInstance; SqlGroup=$g; SamAccountName=$null; DisplayName='(group not resolvable in AD)'; Email=$null; Enabled=$null; LastLogonDate=$null; LastLogonSource=$null; Note=$_.Exception.Message })
            continue
        }

        $members = @(Get-AdGroupMemberRecursive -GroupDn $grp.Dn)
        if (-not $members) {
            $out.Add([pscustomobject]@{ SqlInstance=$SqlInstance; SqlGroup=$g; SamAccountName=$null; DisplayName='(no user members)'; Email=$null; Enabled=$null; LastLogonDate=$null; LastLogonSource=$null; Note=$null })
            continue
        }

        foreach ($m in $members) {
            $lld = $m.LastLogonDate
            $src = 'lastLogonTimestamp (~14d lag)'
            if ($Accurate) {
                $exact = Get-AdAccurateLastLogon -SamAccountName $m.SamAccountName
                if ($exact) { $lld = $exact; $src = 'lastLogon (all DCs)' }
            }
            $out.Add([pscustomobject]@{
                SqlInstance     = $SqlInstance
                SqlGroup        = $g
                SamAccountName  = $m.SamAccountName
                DisplayName     = $m.DisplayName
                Email           = $m.Email
                Enabled         = $m.Enabled
                LastLogonDate   = $lld
                LastLogonSource = $src
                Note            = if ($lld) { $null } else { 'never logged on / no data' }
            })
        }
    }
    Write-Progress -Activity "Expanding AD groups on $SqlInstance" -Completed
    $out
}

# ---------------------------------------------------------------------------
# Run directly when -SqlInstance is supplied; otherwise just load the functions
# (e.g. when dot-sourcing:  . .\Get-SqlAdGroupMemberLastLogon.ps1 ).
if ($SqlInstance) {
    Get-SqlAdGroupMemberLastLogon -SqlInstance $SqlInstance -SqlCredential $SqlCredential -Accurate:$Accurate |
        Sort-Object SqlGroup, SamAccountName
}
