# 📚 Примеры использования Network Scanner

Этот документ содержит подробные примеры использования различных функций Network Scanner.

## 🔍 Примеры сканирования сети

### Базовое сканирование

#### Сканирование одного IP
```
192.168.1.1
```

#### Сканирование диапазона
```
192.168.1.1-192.168.1.254
```

#### Сканирование подсети
```
192.168.1.0/24
```

#### Сканирование нескольких диапазонов
```
192.168.1.1-10,192.168.2.1-20,10.0.0.1-50
```

### Продвинутые примеры

#### Сканирование серверной подсети
```
10.0.0.1-10.0.0.100
```

#### Сканирование DMZ
```
172.16.0.1-172.16.0.50
```

#### Сканирование клиентской сети
```
192.168.100.1-192.168.100.200
```

## 💻 Примеры работы с процессами

### Получение списка процессов

#### Через веб-интерфейс:
1. Откройте главную страницу
2. Введите IP адрес компьютера
3. Нажмите "Получить процессы"
4. Просмотрите таблицу процессов

#### Через PowerShell (Windows):
```powershell
# Прямой вызов скрипта
.\process_helper.ps1 -ComputerName "192.168.1.100"

# Или через fix.ps1 для лучшей совместимости
.\fix.ps1 -ComputerName "192.168.1.100"
```

### Завершение процессов

#### Через веб-интерфейс:
1. Получите список процессов
2. Найдите нужный процесс в таблице
3. Нажмите кнопку "Завершить" рядом с процессом
4. Подтвердите действие

#### Пример завершения процесса по PID:
```bash
# Для Windows (через PowerShell)
taskkill /PID 1234 /F

# Для Linux
kill -9 1234
```

## 🖥️ Примеры VNC подключения

### Базовое подключение

#### Через веб-интерфейс:
1. Откройте главную страницу
2. Найдите нужный компьютер в результатах сканирования
3. Нажмите кнопку "VNC" рядом с IP адресом
4. Введите параметры подключения:
   - **Хост**: IP адрес компьютера
   - **Порт**: 5900 (по умолчанию)
   - **Пароль**: пароль VNC сервера (если требуется)

#### Прямое подключение:
```
http://localhost:8080/vnc_client.html?host=192.168.1.100&port=5900
```

### Продвинутые настройки VNC

#### Подключение с паролем:
```
http://localhost:8080/vnc_client.html?host=192.168.1.100&port=5900&password=mypassword
```

#### Подключение к нестандартному порту:
```
http://localhost:8080/vnc_client.html?host=192.168.1.100&port=5901
```

## 📊 Примеры экспорта данных

### Экспорт результатов сканирования

#### Через веб-интерфейс:
1. Выполните сканирование сети
2. Дождитесь завершения
3. Нажмите кнопку "Экспорт CSV"
4. Файл автоматически скачается

#### Структура CSV файла:
```csv
IP,Status,ResponseTime,Timestamp,Hostname
192.168.1.1,Online,1.23,2024-01-15T10:30:00Z,router.local
192.168.1.2,Online,0.89,2024-01-15T10:30:01Z,server.local
192.168.1.3,Offline,0.00,2024-01-15T10:30:02Z,
```

### Экспорт логов

#### Через веб-интерфейс:
1. Откройте раздел "Логи"
2. Нажмите "Скачать лог"
3. Файл `network_scan.log` будет скачан

#### Структура лог файла:
```
2024-01-15T10:30:00Z	scan_start	{"range":"192.168.1.1-254","total":254}
2024-01-15T10:30:01Z	scan_result	{"ip":"192.168.1.1","status":"Online","response_time":1.23}
2024-01-15T10:30:02Z	scan_complete	{"total":254,"online":15,"offline":239}
```

## 🔧 Примеры конфигурации

### Настройка порта сервера

#### Linux/macOS:
```bash
export ADDR="0.0.0.0:9090"
go run main.go
```

#### Windows:
```cmd
set ADDR=0.0.0.0:9090
go run main.go
```

#### PowerShell:
```powershell
$env:ADDR = "0.0.0.0:9090"
go run main.go
```

### Настройка для продакшена

#### Запуск как сервис (systemd):
```ini
[Unit]
Description=Network Scanner
After=network.target

[Service]
Type=simple
User=scanner
WorkingDirectory=/opt/network-scanner
ExecStart=/opt/network-scanner/scanner
Environment=ADDR=0.0.0.0:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

#### Запуск через Docker:
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o scanner main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/scanner .
COPY --from=builder /app/vnc_client.html .
COPY --from=builder /app/novnc ./novnc
EXPOSE 8080
CMD ["./scanner"]
```

## 🚀 Примеры автоматизации

### Скрипт для регулярного сканирования

#### Bash скрипт:
```bash
#!/bin/bash
# Регулярное сканирование сети

NETWORK_RANGE="192.168.1.1-192.168.1.254"
LOG_FILE="/var/log/network_scan_$(date +%Y%m%d).log"

echo "Starting network scan at $(date)" >> $LOG_FILE

# Запуск сканирования через API
curl -X POST "http://localhost:8080/" \
  -d "action=scan&range=$NETWORK_RANGE" \
  >> $LOG_FILE

echo "Network scan completed at $(date)" >> $LOG_FILE
```

#### PowerShell скрипт:
```powershell
# Регулярное сканирование сети (Windows)

$NetworkRange = "192.168.1.1-192.168.1.254"
$LogFile = "C:\Logs\network_scan_$(Get-Date -Format 'yyyyMMdd').log"

Write-Output "Starting network scan at $(Get-Date)" | Out-File -FilePath $LogFile -Append

# Запуск сканирования через API
$Body = @{
    action = "scan"
    range = $NetworkRange
}

Invoke-RestMethod -Uri "http://localhost:8080/" -Method POST -Body $Body | Out-File -FilePath $LogFile -Append

Write-Output "Network scan completed at $(Get-Date)" | Out-File -FilePath $LogFile -Append
```

### Интеграция с мониторингом

#### Prometheus метрики:
```go
// Пример добавления метрик Prometheus
var (
    scanCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "network_scans_total",
            Help: "Total number of network scans",
        },
        []string{"status"},
    )
    
    scanDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "network_scan_duration_seconds",
            Help: "Duration of network scans",
        },
        []string{"range"},
    )
)
```

## 🔍 Примеры отладки

### Проверка подключения

#### Тест ping:
```bash
ping -c 4 192.168.1.1
```

#### Тест портов:
```bash
nmap -p 5900 192.168.1.100
```

#### Тест VNC сервера:
```bash
vncviewer 192.168.1.100:5900
```

### Проверка логов

#### Просмотр последних записей:
```bash
tail -f network_scan.log
```

#### Фильтрация по типу события:
```bash
grep "scan_result" network_scan.log | tail -20
```

#### Поиск ошибок:
```bash
grep "error" network_scan.log
```

## 📈 Примеры анализа данных

### Анализ результатов сканирования

#### Подсчет онлайн хостов:
```bash
grep '"status":"Online"' network_scan.log | wc -l
```

#### Среднее время отклика:
```bash
grep '"status":"Online"' network_scan.log | \
  jq -r '.response_time' | \
  awk '{sum+=$1; count++} END {print sum/count}'
```

#### Топ хостов по времени отклика:
```bash
grep '"status":"Online"' network_scan.log | \
  jq -r 'select(.response_time > 0) | "\(.ip) \(.response_time)"' | \
  sort -k2 -n
```

Эти примеры помогут вам максимально эффективно использовать Network Scanner для решения различных задач системного администрирования и мониторинга сети.
