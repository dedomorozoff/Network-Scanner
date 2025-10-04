param([string]$TargetIP)

try {
    Write-Host "Trying WMI connection to $TargetIP"
    
    # Получаем процессы через WMI
    $processes = Get-WmiObject -Class Win32_Process -ComputerName $TargetIP -ErrorAction Stop
    
    Write-Host "Found $($processes.Count) processes"
    
    $result = @()
    foreach ($proc in $processes) {
        try {
            $owner = $proc.GetOwner()
            $username = if ($owner.Domain -and $owner.User) { 
                "$($owner.Domain)\$($owner.User)" 
            } else { 
                'SYSTEM' 
            }
        } catch { 
            $username = 'SYSTEM' 
        }
        
        $result += [PSCustomObject]@{
            PID = $proc.ProcessId
            Name = $proc.Name
            CPUP = 0
            MemP = if ($proc.WorkingSetSize) { 
                [math]::Round($proc.WorkingSetSize/1MB, 2) 
            } else { 
                0 
            }
            CmdLine = if ($proc.CommandLine) { 
                $proc.CommandLine 
            } else { 
                if ($proc.ExecutablePath) { $proc.ExecutablePath } else { $proc.Name }
            }
            User = $username
            Status = 'Running'
        }
    }
    
    # Выводим результат в JSON формате
    $result | ConvertTo-Json -Compress
    
} catch {
    $errorMsg = "\`"error\`":\`"WMI failed: $($_.Exception.Message)\`""
    Write-Output ("{$errorMsg}")
}
