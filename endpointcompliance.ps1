$Cache:ComputersHT = @{}

if (Test-Path -Path .\ComputersHT.xml) {
    $Cache:ComputersHT = Import-Clixml .\ComputersHT.xml
}


$Config = [PSCustomObject]@{
    Name = 'Long Format Company Name'
    abbr = 'abbreviation'
}
$Session:processing = $false

function Update-EndpointComplianceData {
    #Clear Cached data
    $Cache:ComputersHT = @{}

    #
    # Active Directory
    #
    $Session:processing = $true

    $ADComputers = Get-ADComputer -filter * -Properties *

    foreach ($ADComputer in $ADComputers) {
        $status = $null
        if ($ADComputer.enabled) {
            $status = 'Enabled'
        } else {
            $status = 'Disabled'
        }
        $Cache:ComputersHT[$ADcomputer.Name] = [PSCustomObject]@{
            Name = $ADcomputer.Name
            AD = $status
            IB = 'Missing'
            FS = 'Missing'
            CS = 'Missing'
        }
    }

    #
    # ImmyBot
    #

    Set-SPSImmyBotWindowsConfiguration -Name $Config.abbr -verbose
    $IBComputers = (invoke-immyApi -endpoint 'computers/paged?skip=0&sortDesc=true&take=5000&includeOffline=true&').results | Where-Object {$_.tenantName -like $Config.Name}

    foreach ($IBComputer in $IBComputers) {
        if ($Cache:ComputersHT.ContainsKey($IBComputer.ComputerName)) {
            $Cache:ComputersHT[$IBComputer.ComputerName].IB = 'Present'
        } else {
            $Cache:ComputersHT[$IBComputer.ComputerName] = [PSCustomObject]@{
                Name = $IBComputer.ComputerName
                AD = 'Missing'
                IB = 'Present'
                FS = 'Missing'
                CS = 'Missing'
            }
        }
    }



    #
    # FreshService
    #

    Set-SPSFreshServiceWindowsConfiguration -Name $Config.abbr

    $FsDepartment = (Get-FsDepartment | where-object {$_.name -like "$($Config.Name)"})[0].id
    $FSAssets = Get-FsAsset | Where-Object {$_.department_id -like $FsDepartment}

    foreach ($FSAsset in $FSAssets) {
        if ($Cache:ComputersHT.ContainsKey($FSAsset.name)) {
            $Cache:ComputersHT[$FSAsset.name].FS = "Present"
        } else {
            $Cache:ComputersHT[$FSAsset.name] = [PSCustomObject]@{
                Name = $FSAsset.name
                AD = 'Missing'
                IB = 'Missing'
                FS = 'Enabled'
                CS = 'Missing'
            }
        }
    }


    #
    # CrowdStrike Falcon
    #

    Request-FalconToken -ClientId $Secret:CrowdStrikeApi.username -ClientSecret $Secret:CrowdStrikeApi.GetNetworkCredential().password -Cloud 'PREFIX-HERE'
    $FalconHosts = Get-FalconHost -Detailed -All
    Write-Output "FalconHosts: $($FalconHosts.count)"
    Revoke-FalconToken

    foreach ($FalconHost in $FalconHosts) {
        if ($Cache:ComputersHT.ContainsKey($FalconHost.hostname)) {
            $Cache:ComputersHT[$FalconHost.hostname].CS = 'Present'
        } else {
            $Cache:computersHT[$FalconHost.hostname] = [PSCustomObject]@{
                Name = $FalconHost.hostname
                AD = 'Missing'
                IB = 'Missing'
                FS = 'Missing'
                CS = 'Enabled'
            }
        }
    }


    #
    # Data Processing
    #


    # Remove/Audit Computers from AD depending on flag in config

    $Cache:ComputersHT.GetEnumerator() | ForEach-Object {
        $Cache:ComputersHT[$_.Key] | Add-Member -MemberType NoteProperty -Name 'SuggestedAction' -Value 'Investigate'
        $Cache:ComputersHT[$_.Key] | Add-Member -MemberType NoteProperty -Name 'ActionTaken' -Value 'Audited'
        if ($Cache:ComputersHT[$_.Key].AD -eq 'Enabled' -and
        $Cache:ComputersHT[$_.Key].IB -eq 'Present' -and
        $Cache:ComputersHT[$_.Key].FS -eq 'Present' -and
        $Cache:ComputersHT[$_.Key].CS -eq 'Present') {
            $Cache:ComputersHT[$_.Key].SuggestedAction = 'None - Compliant'
        }
        if ($Cache:ComputersHT[$_.Key].AD -eq 'Disabled' -and
        $Cache:ComputersHT[$_.Key].IB -eq 'Missing' -and
        $Cache:ComputersHT[$_.Key].FS -eq 'Missing' -and
        $Cache:ComputersHT[$_.Key].CS -eq 'Missing') {
            $Cache:ComputersHT[$_.Key].SuggestedAction = 'Delete From AD'
        }
    }
    $Cache:ComputersHT | Export-Clixml -Path .\ComputersHT.xml
    $Session:processing = $false
    $Cache:UpdateTime = Get-Date
}



New-UDDashboard -Title 'Endpoint Compliance' -Content {

    

    New-UDButton -Text "Update Data" -OnClick {
        Update-EndpointComplianceData
        Sync-UDElement -id 'table'
    }
    

    New-UDDynamic -Id 'table' -Content {
        $columns = @(
            New-UDTableColumn -Property Name -Title "Name" -ShowSort -ShowFilter

            New-UDTableColumn -Property AD -Title "Active Directory" -Render {
                if ($EventData.AD -eq 'Enabled') {
                    New-UDAlert -Severity success -Text $EventData.AD
                } if ($EventData.AD -eq 'Missing') {
                    New-UDAlert -Severity error -Text $EventData.AD
                } if ($EventData.AD -eq 'Disabled') {
                    New-UDAlert -Severity warning -Text $EventData.AD
                }
            } -ShowSort -ShowFilter
            
            New-UDTableColumn -Property IB -Title "Immy Bot" -Render {
                if ($EventData.IB -eq 'Present') {
                    New-UDAlert -Severity success -Text $EventData.IB
                } if ($EventData.IB -eq 'Missing') {
                    New-UDAlert -Severity error -Text $EventData.IB
                }
            } -ShowSort -ShowFilter

            New-UDTableColumn -Property FS -Title "Fresh Service" -Render {
                if ($EventData.FS -eq 'Present') {
                    New-UDAlert -Severity success -Text $EventData.FS
                } if ($EventData.FS -eq 'Missing') {
                    New-UDAlert -Severity error -Text $EventData.FS
                }
            } -ShowSort -ShowFilter

            New-UDTableColumn -Property CS -Title "CrowdStrike" -Render {
                if ($EventData.CS -eq 'Present') {
                    New-UDAlert -Severity success -Text $EventData.CS
                } if ($EventData.CS -eq 'Missing') {
                    New-UDAlert -Severity error -Text $EventData.CS
                }
            } -ShowSort -ShowFilter

            New-UDTableColumn -Property SuggestedAction -Title "Suggested Action" -Render {
                if ($EventData.SuggestedAction -eq 'None - Compliant') {
                    New-UDAlert -Severity success -Text $EventData.SuggestedAction
                } if ($EventData.SuggestedAction -eq 'Delete From AD') {
                    New-UDButton -Text 'Delete From AD'
                } if ($EventData.SuggestedAction -eq 'Investigate') {
                    New-UDAlert -Severity warning -Text $EventData.SuggestedAction
                }
            } -ShowSort -ShowFilter
        )

        if ($Session:processing) {New-UDProgress -Circular -Color Blue}
        New-UDAlert -Id 'UpdateTime' -Text "Last Updated: $Cache:UpdateTime"
        New-UDAlert -Text "Endpoint Count: $($Cache:ComputersHT.count)"
        New-UDTable -Id 'Computers' -Data $Cache:ComputersHT.Values -Columns $Columns -ShowRefresh -ShowPagination:$true -PageSize 10 -PaginationLocation both -ShowSort -ShowFilter -ShowSelection
    } -LoadingComponent {
        "Loading"
    }
}
