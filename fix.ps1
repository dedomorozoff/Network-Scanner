# Исправление для проблемы с получением процессов
# Простое решение для Windows компьютеров

param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName
)

try {
    # Получаем процессы через WMI с лучшей обработкой ошибок  
    # НЕ выводим отладочную информацию в stdout - только JSON
    
    $processes = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName -ErrorAction Stop
    
    $result = @()
    foreach ($proc in $processes) {
        try {
            $owner = $proc.GetOwner()
            if ($owner.Domain -and $owner.User) {
                $username = "$($owner.Domain)\$($owner.User)"
            } else {
                $username = "SYSTEM"
            }
        } catch { 
            $username = "SYSTEM" 
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
            Status = "Running"
        }
    }
    
    # Выводим ТОЛЬКО JSON без дополнительных символов
    $jsonText = $result | ConvertTo-Json -Compress -Depth 10
    # Удаляем все символы кроме печатных ASCII, табуляции, переноса строки
    $cleanJson = $jsonText -replace '[^\x20-\x7E\t\r\n]', ''
    # Удаляем возможные пробелы в начале и конце
    $cleanJson = $cleanJson.Trim()
    # Выводим только чистый JSON
    [Console]::Out.WriteLine($cleanJson)
    
} catch {
    # В случае ошибки выводим JSON с информацией об ошибке
    $errorResult = @{
        success = $false
        error = $_.Exception.Message
    }
    $errorJson = $errorResult | ConvertTo-Json -Compress -Depth 10
    $cleanJson = $errorJson -replace '[^\x20-\x7E\t\r\n]', ''
    $cleanJson = $cleanJson.Trim()
    [Console]::Out.WriteLine($cleanJson)
}
