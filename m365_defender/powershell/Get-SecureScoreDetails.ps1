<#

.Synopsis
Obtain Microsoft 365 Defender Secure Score using Graph API. 

.Description
Connect to Microsoft Graph API using PowerShell and pull all secure score data. Data is processed to calculate score in points and percentages. 
Average score data is pulled from all other tenants, as well as tenants of a similar size, for comparing. All data is outputted in table format. 

.Notes
Author:     Declan Turley   
Version:    1.0
Notes:      Register AAD Application with Graph API permissions of "SecurityEvents.Read.All"

.EXAMPLE
.\Get-SecureScoreDetails.ps1 -TenantId '' -AppId '' -AppSecret ''

.Example
.\Get-SecureScoreDetails.ps1 -TenantId '' -AppId '' -AppSecret '' -showFullScoreDetails

.Example
.\Get-SecureScoreDetails.ps1 -TenantId '' -AppId '' -AppSecret '' -verboseOuput

#>

#Gather paramaters from script execution
Param(
    [Parameter(Mandatory = $true)]
    [string] $TenantId,
    [Parameter(Mandatory = $True)]
    [String] $AppId,
    [Parameter(Mandatory = $True)]
    [String] $AppSecret,
    [switch] $verboseOuput,
    [switch] $showFullScoreDetails
)

#Determine if verbose output is required
if ($verboseOuput) {
    $oldverbose = $VerbosePreference
    $VerbosePreference = "continue" 
}

Write-Verbose "Running script with verbose output enabled"

#Graph resource URIs
$resourceGraphUri = 'https://graph.microsoft.com/'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"

$authBody = [Ordered] @{
    resource      = $resourceGraphUri
    client_id     = $AppId
    client_secret = $AppSecret
    grant_type    = 'client_credentials'
}

Write-Verbose "Getting Graph API token for tenant $($TenantId)"
$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token

Write-Verbose "Setting Graph API URIs"
$secureScoresUri = 'https://graph.microsoft.com/beta/security/secureScores?$top=1'
$secureScoreControlProfileUri = 'https://graph.microsoft.com/beta/security/secureScoreControlProfiles'

#Build table objects for final scores and final reports 
Write-Verbose "Creating Objects for final report"
$DetailedControlScoresTable = New-Object 'System.Collections.Generic.List[System.Object]'
$FinalSecureScoreReport = New-Object 'System.Collections.Generic.List[System.Object]'

# Get latest secure score from Graph Api
Write-Verbose "Getting latest Secure Score from Graph API"
$secureScoreLatest = (Invoke-RestMethod -Headers @{Authorization = "Bearer $($token)" } -Uri $secureScoresUri -Method Get).value

#Set secure score values for my tenant score, maximum score for my tenant, and the avergae score for all tenants and tenants with similar seats
Write-Verbose "Extracting and calculating secure score data"
$myCurrentScore = $secureScoreLatest.CurrentScore
$myMaxScore = $secureScoreLatest.MaxScore
$myCurrentScorePercentage = (($myCurrentScore / $myMaxScore) * 100)
$allTenantsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).AverageScore
$allTenantsAverageIdentity = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).identityScore
$allTenantsAverageApps = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).appsScore
$allTenantsAverageDevice = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).deviceScore
$allTenantsAverageData = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "AllTenants" }).dataScore
$TotalSeatsAverageScore = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).AverageScore
$TotalSeatsAverageIdentity = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).identityScore
$TotalSeatsAverageApps = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).appsScore
$TotalSeatsAverageDevice = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).deviceScore
$TotalSeatsAverageData = ($secureScoreLatest.AverageComparativeScores | ? { $_.Basis -eq "TotalSeats" }).dataScore

#Add combined secure score data to final report
Write-Verbose "Generating overall secure score data"
$finalView = [PSCustomObject]@{
    'Description'         = "OverallScore"
    'myScore'             = $myCurrentScore 
    'maxScore'            = $myMaxScore
    'percentageScore'     = [math]::Round($myCurrentScorePercentage, 2)
    'allTenantAverage'    = [math]::Round($allTenantsAverageScore, 2)
    'similarSeatsAverage' = [math]::Round($TotalSeatsAverageScore, 2)
}
Write-Verbose "Writing overall secure score data to final report"    
$FinalSecureScoreReport.Add($finalView)

#Loop through each Control score and add the details to the control scores table. Also query the control profile for the maximum available score. 
Write-Verbose "Looping through each control profile to obtain maximum scores" 
foreach ($_ in ($secureScoreLatest).ControlScores) {
    $stopLoop = $false
    [int]$Retries = "0"
 
    do {
        try {
            $controlProfileMaxScore = ((Invoke-RestMethod -Headers @{Authorization = "Bearer $($token)" } -Uri "$secureScoreControlProfileUri/$($_.ControlName)" -Method Get)).MaxScore
            Write-Verbose "Successully obtained max score for control profile id $($_.ControlName) ($($controlProfileMaxScore))"
            $stopLoop = $true
        }
        catch {
            if ($Retries -gt 2) {
                Write-Verbose "Unable to obtain max score for control profile id $($_.ControlName)"
                $stopLoop = $true
            }
            else {
                Write-Verbose "Unable to obtain max score. Retrying in 2 seconds for control profile id $($_.ControlName)"
                Start-Sleep -Seconds 2
                $Retries = $Retries + 1
            }
        }
    }
    While ($stopLoop -eq $false)
    
    #Add details for each object to a table
    Write-Verbose "Adding details to table for profile id $($_.ControlName)"
    $DetailedControlScores = [PSCustomObject]@{
        'controlProfile'               = $_.ControlName
        'controlCategory'              = $_.ControlCategory
        'myControlItemScore'           = $_.Score
        'maxControlItemScore'          = $controlProfileMaxScore
    }

    #Add all objects to the combined table
    $DetailedControlScoresTable.Add($DetailedControlScores)
}

#Get the combined score for each Control Category (Identity, Device, Apps, Data etc.). This is in points. 
Write-Verbose "Grouping secure scores by category"
$controlCategoryTable = $DetailedControlScoresTable | Group-Object ControlCategory | % {
    Write-Verbose "Calculating score in points for $($_.Name)"
    New-Object psobject -Property @{
        Category            = $_.Name
        mySumCategoryScore  = ($_.Group | Measure-Object myControlItemScore -Sum).Sum
        maxSumCategoryScore = ($_.Group | Measure-Object maxControlItemScore -Sum).Sum
    }
}
    
#Get the percentage score for each control category. If any score is 0, set average to 0. 
Write-Verbose "Calculating secure scores in percentage"
$report = foreach ($_ in $controlCategoryTable) {
    if ($_.mySumCategoryScore -eq "0") {
        $controlCategoryPercentage = "0"
    }

    else {
        $controlCategoryPercentage = (($_.mySumCategoryScore / $_.maxSumCategoryScore) * 100)
    }

    Write-Verbose "Setting other tenant averages for comparison"
    #Set the average values for all tenants and similar seats
    if ($_.Category -eq "Identity") {
        Write-Verbose "Setting other tenant averages for Identity comparison"
        $allTenantAverage = $allTenantsAverageIdentity
        $similarSeatAverage = $TotalSeatsAverageIdentity
    }
    elseif ($_.Category -eq "Apps") {
        Write-Verbose "Setting other tenant averages for Apps comparison"
        $allTenantAverage = $allTenantsAverageApps
        $similarSeatAverage = $TotalSeatsAverageApps
    }
    elseif ($_.Category -eq "Device") {
        Write-Verbose "Setting other tenant averages for Device comparison"
        $allTenantAverage = $allTenantsAverageDevice
        $similarSeatAverage = $TotalSeatsAverageDevice
    }
    elseif ($_.Category -eq "Data") {
        Write-Verbose "Setting other tenant averages for Data comparison"
        $allTenantAverage = $allTenantsAverageData
        $similarSeatAverage = $TotalSeatsAverageData
    }
    else {
        $allTenantAverage = $null
        $similarSeatAverage = $null
    }

    #Build the final report details
    Write-Verbose "Building final view"
    $finalView = [PSCustomObject]@{
        'Description'         = $_.Category
        'myScore'             = $_.mySumCategoryScore 
        'maxScore'            = $_.maxSumCategoryScore
        'percentageScore'     = [math]::Round($controlCategoryPercentage, 2)
        'allTenantAverage'    = [math]::Round($allTenantAverage, 2)
        'similarSeatsAverage' = [math]::Round($similarSeatAverage, 2)
    }

    #Add Data to final report   
    Write-Verbose "Appending final view to final report" 
    $FinalSecureScoreReport.Add($finalView)
}

Write-Verbose "Displaying secure score final report" 
$FinalSecureScoreReport | Format-Table

if ($showFullScoreDetails) {
    Write-Verbose "Displaying secure score full details report" 
    $DetailedControlScoresTable
}

Write-Verbose "Setting verbose preferences back to orignal"
$VerbosePreference = $oldverbose
