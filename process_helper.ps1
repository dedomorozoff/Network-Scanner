# PowerShell скрипт для получения списка процессов с удаленного компьютера
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName
)

try {
    # Метод 1: WMI через DCOM (наиболее надежный для Windows)
    Write-Host "Attempting WMI DCOM connection to $ComputerName..."
    
    $processes = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -ErrorAction Stop
    
    $result = @()
    foreach ($proc in $processes) {
        try {
            $owner = $proc.GetOwner()
            $username = if ($owner.Domain -and $owner.User) { 
                $owner.Domain + '\' + $owner.User 
            } else { 
                'SYSTEM' 
            }
        } catch { 
            $username = 'SYSTEM' 
        }
        
        $result += [PSCustomObject]@{
            PID = $proc.ProcessId
            Name = $proc.Name
            CPUP = 0  # WMI не предоставляет текущее использование CPU
            MemP = if ($proc.WorkingSetSize) { 
                [math]::Round($proc.WorkingSetSize/1MB, 2) 
            } else { 
                0 
            }
            CmdLine = if ($proc.CommandLine) { 
                $proc.CommandLine 
            } else { 
                $proc.ExecutablePath 
            }
            User = $username
            Status = 'Running'
        }
    }
    
    $result | ConvertTo-Json -Compress
}
catch {
    Write-Output ("`"error`":`"WMI failed: " + $_.Exception.Message + "`"")
    
    # Метод 2: PowerShell Remoting (если WinRM настроен)
    try {
        Write-Host "Attempting PowerShell Remoting to $ComputerName..."
        
        $remoteScript = {
            Get-Process | Select-Object Id, ProcessName, @{
                Name='WorkingSetMB'
                Expression={[math]::Round($_.WorkingSet/1MB,2)}
            }, Path
        }
        
        $processes = Invoke-Command -ComputerName $ComputerName -ScriptBlock $remoteScript -ErrorAction Stop
        
        $result = @()
        foreach ($proc in $processes) {
            $result += [PSCustomObject]@{
                PID = $proc.Id
                Name = $proc.ProcessName
                CPUP = 0
                MemP = $proc.WorkingSetMB
                CmdLine = if ($proc.Path) { $proc.Path } else { $proc.ProcessName }
                User = 'SYSTEM'
                Status = 'Running'
            }
        }
        
        $result | ConvertTo-Json -Compress
    }
    catch {
        Write-Output ("`"error`":`"PowerShell Remoting failed: " + $_.Exception.Message + " (`$_.CategoryInfo.Reason: " + $_.CategoryInfo.Reason + ")`"")
    }
}
