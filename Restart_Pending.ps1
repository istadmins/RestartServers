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
$useEventLog = $true

# Log dosyası yolu (opsiyonel - Event Log başarısız olursa kullanılır)
$logFilePath = "$env:SystemRoot\Logs\RestartServers_$(Get-Date -Format 'yyyyMMdd').log"
$logDirectory = Split-Path $logFilePath -Parent
if (-not (Test-Path $logDirectory)) {
    try { New-Item -ItemType Directory -Path $logDirectory -Force -ErrorAction Stop | Out-Null } catch { }
}

# Temel loglama için fonksiyon
function Write-ScriptLog {
    param(
        [string]$Level, # INFO, WARNING, ERROR
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # 1. Öncelik: Event Log
    if ($script:useEventLog) {
        try {
            $logEntryType = switch ($Level) {
                "WARNING" { [System.Diagnostics.EventLogEntryType]::Warning }
                "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
                default { [System.Diagnostics.EventLogEntryType]::Information }
            }
            Write-EventLog -LogName $LogName -Source $Source -EventId $EventId -EntryType $logEntryType -Message "[$Level] $Message" -ErrorAction Stop
        }
        catch {
            # Event Log yazılamazsa file logging'e geç
            $script:useEventLog = $false
        }
    }
    
    # 2. Fallback: Dosya loglaması
    if (-not $script:useEventLog) {
        try {
            Add-Content -Path $script:logFilePath -Value $logEntry -ErrorAction Stop
        }
        catch {
            # Son çare: hiçbir şey yapma (silent fail)
        }
    }
}

# FailoverClusters modülünü yükle
Import-Module FailoverClusters -ErrorAction SilentlyContinue

# Event Log kaynağı oluştur
if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    try {
        [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
        Write-ScriptLog -Level INFO -Message "Event Log kaynağı ($Source) başarıyla oluşturuldu."
    }
    catch {
        # Event Log kaynağı oluşturulamadı, dosya loglamasına geçilecek
        $useEventLog = $false
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
    try {
        $domainPath = (Get-ADDomain).DistinguishedName
        Write-ScriptLog -Level INFO -Message "Domain yolu alındı: $domainPath"
    }
    catch {
        Write-ScriptLog -Level ERROR -Message "Active Directory erişim hatası: $($_.Exception.Message)"
        throw "Active Directory'ye erişilemiyor. Script sonlandırılıyor."
    }
    
    # AD Filter - String formatında
    $adFilter = '(OperatingSystem -like "*Server*") -and (-not (Description -like "*cluster*"))'
    
    $serversFromAD = Get-ADComputer -Filter $adFilter -SearchBase $domainPath -Properties Name, Description, OperatingSystem | Select-Object -ExpandProperty Name
    Write-ScriptLog -Level INFO -Message "AD'den $($serversFromAD.Count) adet ham sunucu adı alındı."

    # Sunucu isimlerini temizle - Nokta karakteri escape edildi
    $cleanedServers = $serversFromAD | Where-Object { $_ -match '^[a-zA-Z0-9\-_\.]+$' }
    
    Write-ScriptLog -Level INFO -Message "Kontrol edilecek temizlenmiş sunucu sayısı: $($cleanedServers.Count)."

    # Restart pending sunucuları bul
    $restartPendingServers = [System.Collections.Generic.List[PSCustomObject]]::new()
    
    foreach ($serverName_LoopVar in $cleanedServers) {
        try {
            if (Test-Connection -ComputerName $serverName_LoopVar -Count 1 -Quiet -ErrorAction Stop) {
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
                    $restartPendingServers.Add([PSCustomObject]@{
                        ServerName  = $serverName_LoopVar
                        Status      = "Restart Pending"
                        IsCluster   = $false
                    })
                }
            }
            else {
                Write-ScriptLog -Level WARNING -Message "Sunucuya ping BAŞARISIZ: '$serverName_LoopVar'. Atlandı."
            }
        }
        catch {
            $errorMsg = $_.Exception.Message
            $errorLine = if ($_.InvocationInfo.ScriptLineNumber) { $_.InvocationInfo.ScriptLineNumber } else { "N/A" }
            Write-ScriptLog -Level ERROR -Message "Sunucu ($serverName_LoopVar) durumu kontrol edilirken hata (Satır: $errorLine): $errorMsg"
        }
    }
    
    if ($restartPendingServers.Count -eq 0) {
        Write-ScriptLog -Level INFO -Message "Yeniden başlatma bekleyen sunucu bulunamadı. Script sonlandırılıyor."
        exit 0
    }

    # Sunucuları isme göre grupla
    $groupedServers = @{}
    foreach ($server_PSObject in $restartPendingServers) {
        $currentServerNameForGrouping = $server_PSObject.ServerName
        if ($currentServerNameForGrouping -match '(.*[a-zA-Z\-]+)(\d*)$') {
            $prefix = $matches[1]
            if (-not $groupedServers.ContainsKey($prefix)) { 
                $groupedServers[$prefix] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $groupedServers[$prefix].Add($server_PSObject)
        }
        else {
            $fallbackPrefix = "FALLBACK_" + $currentServerNameForGrouping
            if (-not $groupedServers.ContainsKey($fallbackPrefix)) { 
                $groupedServers[$fallbackPrefix] = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
            $groupedServers[$fallbackPrefix].Add($server_PSObject)
        }
    }

    $serversToRestart = [System.Collections.Generic.List[string]]::new()
    $restartedServers = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($groupPrefix_LoopVar in $groupedServers.Keys) {
        $serversInGroup = $groupedServers[$groupPrefix_LoopVar]
        Write-ScriptLog -Level INFO -Message "Grup işleniyor: '$groupPrefix_LoopVar' ($($serversInGroup.Count) sunucu)"

        if ($ExcludedPrefixes -contains $groupPrefix_LoopVar) {
            Write-ScriptLog -Level INFO -Message "'$groupPrefix_LoopVar' grubu hariç tutuldu."
            continue
        }

        # ===== CLUSTER MANTIĞI =====
        $isClusterGroup = $false
        $serverToRestartCandidate = $null
        $clusterName = $null
        
        if ($serversInGroup.Count -gt 0) {
            $candidateServerNameForClusterCheck = $serversInGroup[0].ServerName
            
            try {
                $clusterAnalysis = Invoke-Command -ComputerName $candidateServerNameForClusterCheck -ArgumentList (, $ClusterGroupFilters) -ScriptBlock {
                    param($Filters)
                    
                    Import-Module FailoverClusters -ErrorAction SilentlyContinue
                    
                    # Get-Cluster komutunun var olup olmadığını kontrol et
                    if (Get-Command "Get-Cluster" -ErrorAction SilentlyContinue) {
                        $cl = Get-Cluster -ErrorAction SilentlyContinue
                    }
                    else {
                        $cl = $null
                    }
                    
                    if ($cl) {
                        # 1. Filtreye uyan Rolleri (Group) bul
                        $allGroups = Get-ClusterGroup
                        $matchedGroups = @()
                        if ($Filters) {
                            foreach ($f in $Filters) {
                                $matchedGroups += $allGroups | Where-Object { $_.Name -like $f }
                            }
                        }
                        else {
                            $matchedGroups = $allGroups
                        }
                        
                        # 2. Bu rollerin şu anki SAHİBİ (Owner) olan node'ları bul
                        $activeNodeNames = @()
                        foreach ($g in $matchedGroups) {
                            if ($g.OwnerNode -is [string]) {
                                $activeNodeNames += $g.OwnerNode
                            }
                            elseif ($g.OwnerNode.Name) {
                                $activeNodeNames += $g.OwnerNode.Name
                            }
                        }
                        $activeNodeNames = $activeNodeNames | Select-Object -Unique

                        # 3. Clusterdaki tüm node'ları bul
                        $allNodes = Get-ClusterNode | Where-Object { $_.State -eq "Up" } | Select-Object -ExpandProperty Name

                        return [PSCustomObject]@{
                            IsCluster   = $true
                            ClusterName = $cl.Name
                            ActiveNodes = $activeNodeNames
                            AllNodes    = $allNodes
                        }
                    }
                    else {
                        return [PSCustomObject]@{ IsCluster = $false }
                    }
                } -ErrorAction Stop

                if ($clusterAnalysis.IsCluster) {
                    $isClusterGroup = $true
                    $clusterName = $clusterAnalysis.ClusterName
                    Write-ScriptLog -Level INFO -Message "Cluster Tespit Edildi: $clusterName. Analiz yapılıyor..."
                    
                    # Cluster bilgisini sunucu objelerine ekle
                    foreach ($srv in $serversInGroup) {
                        $srv.IsCluster = $true
                    }
                    
                    $actives = $clusterAnalysis.ActiveNodes
                    
                    # Pasif node'ları bul
                    $availablePassiveNodes = @()
                    foreach ($srv in $serversInGroup) {
                        if ($actives -notcontains $srv.ServerName) {
                            $availablePassiveNodes += $srv.ServerName
                        }
                        else {
                            Write-ScriptLog -Level INFO -Message "Atlanan Aktif Node: $($srv.ServerName) (Üzerinde çalışan roller var)"
                        }
                    }

                    if ($availablePassiveNodes.Count -gt 0) {
                        $serverToRestartCandidate = $availablePassiveNodes | Get-Random
                        Write-ScriptLog -Level INFO -Message "CLUSTER PASİF NODE SEÇİLDİ (Grup: '$groupPrefix_LoopVar'): '$serverToRestartCandidate'"
                    }
                    else {
                        Write-ScriptLog -Level WARNING -Message "Cluster ($clusterName) için restart bekleyen PASİF bir node bulunamadı. Hepsi aktif veya ulaşılamaz."
                    }
                }
                else {
                    Write-ScriptLog -Level INFO -Message "Sunucu '$candidateServerNameForClusterCheck' bir cluster üyesi değil."
                }

            }
            catch {
                $errorMsg = $_.Exception.Message
                Write-ScriptLog -Level WARNING -Message "Cluster kontrolü sırasında hata oluştu veya erişilemedi. Non-cluster olarak devam ediliyor. Hata: $errorMsg"
                $isClusterGroup = $false
            }
        }
        # ===== SON: CLUSTER MANTIĞI =====

        # Eğer cluster değilse veya cluster'da aday bulunamadıysa rastgele seç
        if (-not $isClusterGroup -or (-not $serverToRestartCandidate -and $isClusterGroup)) {
            if ($isClusterGroup) {
                Write-ScriptLog -Level INFO -Message "Cluster mantığı aday bulamadığı için non-cluster rastgele seçim mantığına geçildi."
            }
            if ($serversInGroup.Count -gt 0) {
                $randomIndex = Get-Random -Maximum $serversInGroup.Count
                $serverToRestartCandidate = $serversInGroup[$randomIndex].ServerName
                Write-ScriptLog -Level INFO -Message "NON-CLUSTER RASTGELE SUNUCU SEÇİLDİ (Grup: '$groupPrefix_LoopVar'): '$serverToRestartCandidate'"
            }
        }

        if ($serverToRestartCandidate) {
            $serversToRestart.Add($serverToRestartCandidate)
        }
        else { 
            Write-ScriptLog -Level WARNING -Message "Grup '$groupPrefix_LoopVar' için yeniden başlatılacak aday SEÇİLEMEDİ." 
        }

    } # End foreach group

    if ($serversToRestart.Count -eq 0) {
        Write-ScriptLog -Level INFO -Message "Tüm gruplar işlendi. Yeniden başlatılacak uygun sunucu bulunamadı."
        exit 0
    }

    # Local machine koruması (sona alma)
    if ($serversToRestart -contains $localMachine) {
        $serversToRestart.Remove($localMachine)
        $serversToRestart.Add($localMachine)
        Write-ScriptLog -Level WARNING -Message "Yerel makine ($localMachine) listeye eklendi ancak SONA kaydırıldı."
    }

    # Unique yap
    $serversToRestart = $serversToRestart | Select-Object -Unique
    Write-ScriptLog -Level INFO -Message "YENİDEN BAŞLATILACAK NİHAİ LİSTE: $($serversToRestart -join ', ')"

    # Restart işlemi
    foreach ($serverToRestart_Item in $serversToRestart) {
        if ($TestMode) {
            Write-ScriptLog -Level INFO -Message "[TEST MODU] Sunucu '$serverToRestart_Item' yeniden BAŞLATILACAKTI."
            $restartedServers.Add([PSCustomObject]@{ 
                ServerName = $serverToRestart_Item
                Status = "Restart Pending (Test Mode - Would Restart)"
                IsCluster = ($restartPendingServers | Where-Object { $_.ServerName -eq $serverToRestart_Item }).IsCluster
            })
        }
        else {
            Write-ScriptLog -Level INFO -Message "Yeniden başlatılıyor: $serverToRestart_Item"
            try {
                Restart-Computer -ComputerName $serverToRestart_Item -Force -Wait -Timeout $MaxWaitSeconds -ErrorAction Stop
                Write-ScriptLog -Level INFO -Message "Sunucu '$serverToRestart_Item' başarıyla yeniden başlatıldı."
                $restartedServers.Add([PSCustomObject]@{ 
                    ServerName = $serverToRestart_Item
                    Status = "Restarted"
                    IsCluster = ($restartPendingServers | Where-Object { $_.ServerName -eq $serverToRestart_Item }).IsCluster
                })
            }
            catch {
                $errorMsg = $_.Exception.Message
                Write-ScriptLog -Level ERROR -Message "Sunucu '$serverToRestart_Item' yeniden başlatılırken hata: $errorMsg"
                $restartedServers.Add([PSCustomObject]@{ 
                    ServerName = $serverToRestart_Item
                    Status = "Restart Failed"
                    IsCluster = ($restartPendingServers | Where-Object { $_.ServerName -eq $serverToRestart_Item }).IsCluster
                })
            }
        }
    }

    # Raporlama Bölümü
    $allServersReport = [System.Collections.Generic.List[PSCustomObject]]::new()
    $list1ForReport = @($restartPendingServers.ServerName) 
    $list2ForReport = @($restartedServers.ServerName)  
    $combinedServerListForReport = ($list1ForReport + $list2ForReport) | Select-Object -Unique | Sort-Object
    
    foreach ($serverNameInReportScope in $combinedServerListForReport) {
        $serverInRestartedList = $restartedServers | Where-Object { $_.ServerName -eq $serverNameInReportScope }
        if ($serverInRestartedList) {
            $allServersReport.Add($serverInRestartedList)
        }
        else {
            $serverInOriginalPendingList = $restartPendingServers | Where-Object { $_.ServerName -eq $serverNameInReportScope }
            if ($serverInOriginalPendingList) {
                $statusForNotSelected = if ($TestMode) { "Restart Pending (Test Mode - Not Selected)" } else { "Restart Pending (Not Selected)" }
                $allServersReport.Add([PSCustomObject]@{ 
                    ServerName = $serverInOriginalPendingList.ServerName
                    Status = $statusForNotSelected
                    IsCluster = $serverInOriginalPendingList.IsCluster
                })
            }
        }
    }

    # HTML tablosu - Cluster bilgisi eklendi
    $htmlTable = $allServersReport | Sort-Object ServerName | Select-Object ServerName, Status, @{Name="Cluster"; Expression={if($_.IsCluster){"Yes"}else{"No"}}} | ConvertTo-Html -Fragment
    
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
        tr:hover { background-color: #f1f3f5; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .status-restart-pending { color: #dc3545; font-weight: bold; }
        .status-restarted { color: #28a745; font-weight: bold; }
        .status-restart-failed { color: #D8000C; background-color: #FFBABA; font-weight: bold; padding: 5px;}
        .status-test-would-restart { color: #007bff; background-color: #cfe2ff; font-weight: bold; padding: 5px;}
        .footer { text-align: center; margin-top: 30px; font-size: 12px; color: #6c757d; }
    </style>
</head>
<body>
    <h2>Server Durum Raporu $scriptMode</h2>
    <p style="text-align: center; color: #6c757d;">Rapor Tarihi: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss") | Çalışan Makine: $localMachine</p>
    $htmlTable
    <div class="footer">
        <p>Bu rapor otomatik olarak oluşturulmuştur.</p>
    </div>
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
            $errorMsg = $_.Exception.Message
            Write-ScriptLog -Level ERROR -Message "E-posta gönderilemedi: $errorMsg"
        }
    }
    else {
        Write-ScriptLog -Level WARNING -Message "Rapor boş olduğu için e-posta gönderilmedi."
    }
    
    Write-ScriptLog -Level INFO -Message "Script tamamlandı."
}
catch {
    $errorMsg = $_.Exception.Message
    $errorLine = if ($_.InvocationInfo.ScriptLineNumber) { $_.InvocationInfo.ScriptLineNumber } else { "N/A" }
    Write-ScriptLog -Level ERROR -Message "[CRITICAL] Script hatası (Satır: $errorLine): $errorMsg"
    Write-ScriptLog -Level ERROR -Message "Stack Trace: $($_.ScriptStackTrace)"
    exit 1
}