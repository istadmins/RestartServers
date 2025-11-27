param (
    [string]$Source = "RestartServers",
    [string]$LogName = "Application",
    [string]$SmtpServer = "mail.ads.sita.net",
    [int]$SmtpPort = 25,
    [string]$From = "$env:COMPUTERNAME@ads.sita.aero",
    [string]$To = "IST.CUTE.Admins@sita.aero",
    [int]$MaxWaitSeconds = 300,
    [string[]]$ExcludedPrefixes = @("ISTT-AMS-SQL"),
    [string[]]$ClusterGroupFilters = @("*MSMQ*", "*IB03*"),
    [switch]$TestMode = $false
)

# Script'in çalıştığı makineyi al
$localMachine = $env:COMPUTERNAME
$EventId = 9999 # Sabit Event ID

# Temel loglama için fonksiyon
function Write-ScriptLog {
    param(
        [string]$Level, # INFO, WARNING, ERROR
        [string]$Message
    )
    $logEntryType = switch ($Level) {
        "WARNING" { [System.Diagnostics.EventLogEntryType]::Warning }
        "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
        default { [System.Diagnostics.EventLogEntryType]::Information }
    }
    Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $logEntryType -Message "[$Level] $Message"
}

# FailoverClusters modülünü yükle (Lokal makine için opsiyonel, remote komutlarda şart)
Import-Module FailoverClusters -ErrorAction SilentlyContinue

# Event Log kaynağı oluştur
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    try {
        [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
        Write-ScriptLog -Level INFO -Message "Event Log kaynağı ($Source) başarıyla oluşturuldu."
    }
    catch {
        # Bu durumda log yazılamaz.
    }
}

# Script başlangıç bilgisi
$scriptMode = if ($TestMode) { "[TEST MODU AKTİF]" } else { "[NORMAL MOD]" }
Write-ScriptLog -Level INFO -Message "------------------------------------------------------------"
Write-ScriptLog -Level INFO -Message "$scriptMode Server yeniden başlatma scripti başlatıldı - $(Get-Date)"
Write-ScriptLog -Level INFO -Message "Çalışan Makine: $localMachine, SMTP Sunucusu: $($SmtpServer):$SmtpPort, Alıcı: $To"

if ($TestMode) {
    Write-ScriptLog -Level INFO -Message "Script test modunda çalışıyor. Sunucular yeniden BAŞLATILMAYACAK."
}

try {
    # Domaindeki sunucuları al
    $domainPath = (Get-ADDomain).DistinguishedName
    $adFilter = {
        (OperatingSystem -like "*Server*") -and
        (-not (Description -like "*cluster*"))
    }
    $serversFromAD = Get-ADComputer -Filter $adFilter -SearchBase $domainPath -Properties Name, Description, OperatingSystem | Select-Object -ExpandProperty Name
    Write-ScriptLog -Level INFO -Message "AD'den $($serversFromAD.Count) adet ham sunucu adı alındı."

    $cleanedServers = $serversFromAD | Where-Object { $_ -match '^[a-zA-Z0-9\-._]+$' }
    
    Write-ScriptLog -Level INFO -Message "Kontrol edilecek temizlenmiş sunucu sayısı: $($cleanedServers.Count)."

    $restartPendingServers = @()
    foreach ($serverName_LoopVar in $cleanedServers) {
        try {
            if (Test-Connection -ComputerName $serverName_LoopVar -Count 2 -Quiet -ErrorAction Stop) {
                $result = Invoke-Command -ComputerName $serverName_LoopVar -ScriptBlock {
                    $regPendingCBS = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
                    $regPendingWU = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
                    if ($regPendingCBS -or $regPendingWU) { 
                        return $true 
                    }
                    return $false
                } -ErrorAction Stop

                if ($result) {
                    Write-ScriptLog -Level INFO -Message "Yeniden başlatma BEKLİYOR: '$serverName_LoopVar'"
                    $restartPendingServers += [PSCustomObject]@{
                        ServerName = $serverName_LoopVar
                        Status     = "Restart Pending"
                    }
                }
            }
            else {
                Write-ScriptLog -Level WARNING -Message "Sunucuya ping BAŞARISIZ: '$serverName_LoopVar'. Atlantı."
            }
        }
        catch {
            Write-ScriptLog -Level ERROR -Message "Sunucu ($serverName_LoopVar) durumu kontrol edilirken hata: $($_.Exception.Message)"
        }
    }
    
    if ($restartPendingServers.Count -eq 0) {
        Write-ScriptLog -Level INFO -Message "Yeniden başlatma bekleyen sunucu bulunamadı. Script sonlandırılıyor."
        exit
    }

    # Sunucuları isme göre grupla
    $groupedServers = @{}
    foreach ($server_PSObject in $restartPendingServers) {
        $currentServerNameForGrouping = $server_PSObject.ServerName
        if ($currentServerNameForGrouping -match '(.*[a-zA-Z\-]+)(\d*)$') {
            $prefix = $matches[1]
            if (-not $groupedServers.ContainsKey($prefix)) { $groupedServers[$prefix] = @() }
            $groupedServers[$prefix] += $server_PSObject
        }
        else {
            $fallbackPrefix = "FALLBACK_" + $currentServerNameForGrouping
            if (-not $groupedServers.ContainsKey($fallbackPrefix)) { $groupedServers[$fallbackPrefix] = @() }
            $groupedServers[$fallbackPrefix] += $server_PSObject
        }
    }

    $serversToRestart = @()
    $restartedServers = @() 

    foreach ($groupPrefix_LoopVar in $groupedServers.Keys) {
        $serversInGroup = $groupedServers[$groupPrefix_LoopVar]
        Write-ScriptLog -Level INFO -Message "Grup işleniyor: '$groupPrefix_LoopVar' ($($serversInGroup.Count) sunucu)"
        $randomIndex = Get-Random -Maximum $serversInGroup.Count
        $serverToRestartCandidate = $serversInGroup[$randomIndex].ServerName
        Write-ScriptLog -Level INFO -Message "NON-CLUSTER RASTGELE SUNUCU SEÇİLDİ (Grup: '$groupPrefix_LoopVar'): '$serverToRestartCandidate'"
    }
}

if ($serverToRestartCandidate) {
    $serversToRestart += $serverToRestartCandidate
}
else { 
    Write-ScriptLog -Level WARNING -Message "Grup '$groupPrefix_LoopVar' için yeniden başlatılacak aday SEÇİLEMEDİ." 
}

} # End foreach group

if ($serversToRestart.Count -eq 0) {
    Write-ScriptLog -Level INFO -Message "Tüm gruplar işlendi. Yeniden başlatılacak uygun sunucu bulunamadı."
    exit
}

# Local machine koruması (sona alma)
if ($serversToRestart -contains $localMachine) {
    $tempArray = @($serversToRestart | Where-Object { $_ -ne $localMachine })
    $tempArray += $localMachine
    $serversToRestart = $tempArray
}

$serversToRestart = $serversToRestart | Select-Object -Unique
Write-ScriptLog -Level INFO -Message "YENİDEN BAŞLATILACAK NİHAİ LİSTE: $($serversToRestart -join ', ')"

foreach ($serverToRestart_Item in $serversToRestart) {
    if ($TestMode) {
        Write-ScriptLog -Level INFO -Message "[TEST MODU] Sunucu '$serverToRestart_Item' yeniden BAŞLATILACAKTI."
        $restartedServers += [PSCustomObject]@{ ServerName = $serverToRestart_Item; Status = "Restart Pending (Test Mode - Would Restart)" }
    }
    else {
        Write-ScriptLog -Level INFO -Message "Yeniden başlatılıyor: $serverToRestart_Item"
        try {
            Restart-Computer -ComputerName $serverToRestart_Item -Force -Wait -Timeout $MaxWaitSeconds -ErrorAction Stop
            Write-ScriptLog -Level INFO -Message "Sunucu '$serverToRestart_Item' başarıyla yeniden başlatıldı."
            $restartedServers += [PSCustomObject]@{ ServerName = $serverToRestart_Item; Status = "Restarted" }
        }
        catch {
            Write-ScriptLog -Level ERROR -Message "Sunucu '$serverToRestart_Item' yeniden başlatılırken hata: $($_.Exception.Message)"
            $restartedServers += [PSCustomObject]@{ ServerName = $serverToRestart_Item; Status = "Restart Failed" }
        }
    }
}

# Raporlama Bölümü
$allServersReport = @()
$list1ForReport = @($restartPendingServers.ServerName) 
$list2ForReport = @($restartedServers.ServerName)  
$combinedServerListForReport = ($list1ForReport + $list2ForReport) | Select-Object -Unique | Sort-Object
    
foreach ($serverNameInReportScope in $combinedServerListForReport) {
    $serverInRestartedList = $restartedServers | Where-Object { $_.ServerName -eq $serverNameInReportScope }
    if ($serverInRestartedList) {
        $allServersReport += $serverInRestartedList
    }
    else {
        $serverInOriginalPendingList = $restartPendingServers | Where-Object { $_.ServerName -eq $serverNameInReportScope }
        if ($serverInOriginalPendingList) {
            $statusForNotSelected = if ($TestMode) { "Restart Pending (Test Mode - Not Selected)" } else { "Restart Pending (Not Selected)" }
            $allServersReport += [PSCustomObject]@{ ServerName = $serverInOriginalPendingList.ServerName; Status = $statusForNotSelected }
        }
    }
}

$htmlTable = $allServersReport | Sort-Object ServerName | ConvertTo-Html -Fragment -Property ServerName, Status
    
# HTML CSS ve Body
$emailBody = @"
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Server Durum Raporu $scriptMode</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; margin: 0; padding: 20px; color: #495057; }
        h2 { color: #343a40; text-align: center; margin-bottom: 30px; font-weight: 300; }
        table { width: 100%; border-collapse: separate; border-spacing: 0; margin: 20px 0; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05); border-radius: 8px; overflow: hidden; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #dee2e6; font-size: 14px; }
        th { background-color: #6f42c1; color: white; font-weight: 600; font-size: 15px; text-transform: uppercase; letter-spacing: 0.5px; }
        .status-restart-pending { color: #dc3545; font-weight: bold; }
        .status-restarted { color: #28a745; font-weight: bold; }
        .status-restart-failed { color: #D8000C; background-color: #FFBABA; font-weight: bold;}
        .status-test-would-restart { color: #007bff; background-color: #cfe2ff; font-weight: bold;}
    </style>
</head>
<body>
    <h2>Server Durum Raporu $scriptMode</h2>
    $htmlTable
</body>
</html>
"@

if ($allServersReport.Count -gt 0) {
    try {
        $SmtpClient = New-Object Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $Message = New-Object System.Net.Mail.MailMessage($From, $To, "Server Durum Raporu $scriptMode - $localMachine", $emailBody)
        $Message.IsBodyHtml = $true
        $SmtpClient.Send($Message)
        Write-ScriptLog -Level INFO -Message "E-posta başarıyla gönderildi."
    }
    catch {
        Write-ScriptLog -Level ERROR -Message "E-posta gönderilemedi: $($_.Exception.Message)"
    }
}
Write-ScriptLog -Level INFO -Message "Script tamamlandı."
}
catch {
    Write-ScriptLog -Level ERROR -Message "[CRITICAL] Script hatası: $($_.Exception.Message)"
}