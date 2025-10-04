# 🔧 Техническая документация Network Scanner

Этот документ содержит подробную техническую информацию о внутренней архитектуре и реализации Network Scanner.

## 🏗️ Архитектура системы

### Общая схема
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Browser   │◄──►│   Go Server     │◄──►│  Target Hosts   │
│                 │    │                 │    │                 │
│ - HTML/CSS/JS   │    │ - HTTP Server   │    │ - VNC Servers   │
│ - noVNC Client  │    │ - WebSocket     │    │ - WMI/PowerShell│
│ - Real-time UI  │    │ - Process Mgmt  │    │ - Network       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Компоненты системы

#### 1. Go Backend (`main.go`)
- **HTTP сервер** на стандартной библиотеке Go
- **WebSocket прокси** для VNC соединений
- **Обработка процессов** через PowerShell/WMI
- **Сканирование сети** с использованием goroutines
- **Логирование** в JSON формате

#### 2. Frontend (`vnc_client.html`)
- **noVNC клиент** для VNC подключений
- **Адаптивный интерфейс** с современным дизайном
- **WebSocket соединение** для реального времени
- **Обработка событий** клавиатуры и мыши

#### 3. PowerShell скрипты
- **`process_helper.ps1`** - основной скрипт для получения процессов
- **`process_simple.ps1`** - упрощенная версия
- **`fix.ps1`** - исправления для совместимости

## 📡 API Спецификация

### HTTP Endpoints

#### `GET /` - Главная страница
Возвращает HTML интерфейс приложения.

#### `POST /` - API обработчик
Обрабатывает различные действия через параметр `action`.

**Поддерживаемые действия:**
- `scan` - запуск сканирования сети
- `processes` - получение списка процессов
- `kill` - завершение процесса
- `interfaces` - получение сетевых интерфейсов
- `log_tail` - получение последних строк лога
- `log_download` - скачивание лог файла
- `export` - экспорт результатов в CSV

#### `GET /scan/stream` - SSE поток сканирования
Server-Sent Events поток для получения результатов сканирования в реальном времени.

**Формат данных:**
```json
{
  "ip": "192.168.1.1",
  "status": "Online",
  "response_time": 1.23,
  "timestamp": "2024-01-15T10:30:00Z",
  "hostname": "router.local",
  "index": 1,
  "total": 254,
  "progress": 0.39
}
```

#### `GET /vnc_client.html` - VNC клиент
Возвращает HTML страницу с VNC клиентом.

#### `GET /websockify` - WebSocket прокси
WebSocket прокси для подключения к VNC серверам.

**Параметры:**
- `host` - IP адрес VNC сервера
- `port` - порт VNC сервера

### Структуры данных

#### ScanResult
```go
type ScanResult struct {
    IP           string  `json:"ip"`
    Status       string  `json:"status"`
    ResponseTime float64 `json:"response_time"`
    Timestamp    string  `json:"timestamp"`
    Hostname     string  `json:"hostname,omitempty"`
    Index        int     `json:"index,omitempty"`
    Total        int     `json:"total,omitempty"`
    Progress     float64 `json:"progress,omitempty"`
}
```

#### ProcessInfo
```go
type ProcessInfo struct {
    PID     int     `json:"PID"`
    Name    string  `json:"Name"`
    CPUP    float64 `json:"CPUP"`
    MemP    float64 `json:"MemP"`
    CmdLine string  `json:"CmdLine"`
    User    string  `json:"User"`
    Status  string  `json:"Status"`
}
```

## 🔍 Алгоритмы сканирования

### Парсинг диапазонов IP

#### Поддерживаемые форматы:
1. **Одиночный IP**: `192.168.1.1`
2. **Диапазон**: `192.168.1.1-192.168.1.254`
3. **CIDR**: `192.168.1.0/24`
4. **Множественные**: `192.168.1.1-10,192.168.2.1-20`

#### Алгоритм парсинга:
```go
func parseIPRange(rangeStr string) ([]string, error) {
    var ips []string
    
    // Разделение по запятым для множественных диапазонов
    ranges := strings.Split(rangeStr, ",")
    
    for _, r := range ranges {
        r = strings.TrimSpace(r)
        
        if strings.Contains(r, "-") {
            // Диапазон IP
            ips = append(ips, parseRange(r)...)
        } else if strings.Contains(r, "/") {
            // CIDR нотация
            ips = append(ips, parseCIDR(r)...)
        } else {
            // Одиночный IP
            ips = append(ips, r)
        }
    }
    
    return ips, nil
}
```

### Ping тестирование

#### Реализация:
```go
func pingHost(ip string) (bool, float64) {
    var cmd *exec.Cmd
    
    if runtime.GOOS == "windows" {
        cmd = exec.Command("ping", "-n", "1", "-w", "3000", ip)
    } else {
        cmd = exec.Command("ping", "-c", "1", "-W", "3", ip)
    }
    
    start := time.Now()
    err := cmd.Run()
    duration := time.Since(start).Seconds()
    
    return err == nil, duration
}
```

### Параллельное сканирование

#### Горутины и каналы:
```go
func scanNetwork(ips []string) <-chan ScanResult {
    results := make(chan ScanResult, len(ips))
    semaphore := make(chan struct{}, maxConcurrency)
    
    for i, ip := range ips {
        go func(index int, targetIP string) {
            semaphore <- struct{}{} // Захват семафора
            
            online, responseTime := pingHost(targetIP)
            status := "Offline"
            if online {
                status = "Online"
            }
            
            results <- ScanResult{
                IP:           targetIP,
                Status:       status,
                ResponseTime: responseTime,
                Timestamp:    time.Now().Format(time.RFC3339),
                Index:        index + 1,
                Total:        len(ips),
                Progress:     float64(index+1) / float64(len(ips)),
            }
            
            <-semaphore // Освобождение семафора
        }(i, ip)
    }
    
    return results
}
```

## 💻 Управление процессами

### Windows (WMI)

#### Получение процессов:
```powershell
$processes = Get-WmiObject -Class Win32_Process -ComputerName $ComputerName
foreach ($proc in $processes) {
    $owner = $proc.GetOwner()
    $username = if ($owner.Domain -and $owner.User) { 
        "$($owner.Domain)\$($owner.User)" 
    } else { 
        'SYSTEM' 
    }
    
    [PSCustomObject]@{
        PID = $proc.ProcessId
        Name = $proc.Name
        MemP = [math]::Round($proc.WorkingSetSize/1MB, 2)
        User = $username
        Status = 'Running'
    }
}
```

#### Завершение процесса:
```powershell
Stop-Process -Id $PID -Force
```

### Linux/macOS (SSH)

#### Получение процессов:
```bash
ssh $HOST "ps aux --no-headers | awk '{print \$2,\$11,\$3,\$4,\$1}'"
```

#### Завершение процесса:
```bash
ssh $HOST "kill -9 $PID"
```

## 🖥️ VNC интеграция

### WebSocket прокси

#### Реализация прокси:
```go
func vncProxyHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    port := r.URL.Query().Get("port")
    
    // Установка WebSocket соединения
    upgrader := websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
    }
    
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Подключение к VNC серверу
    vncAddr := fmt.Sprintf("%s:%s", host, port)
    vncConn, err := net.Dial("tcp", vncAddr)
    if err != nil {
        return
    }
    defer vncConn.Close()
    
    // Проксирование данных
    go proxyData(conn, vncConn)
    proxyData(vncConn, conn)
}

func proxyData(dst, src net.Conn) {
    io.Copy(dst, src)
}
```

### noVNC клиент

#### Инициализация:
```javascript
const rfb = new RFB(screen, url, {
    credentials: password ? { password: password } : undefined
});

rfb.addEventListener('connect', () => {
    updateStatus('Подключен', 'status-connected');
});

rfb.addEventListener('disconnect', (e) => {
    updateStatus('Отключен', 'status-disconnected');
});
```

## 📊 Логирование

### Формат логов

#### Структура записи:
```
TIMESTAMP	TYPE	JSON_DATA
```

#### Примеры записей:
```
2024-01-15T10:30:00Z	scan_start	{"range":"192.168.1.1-254","total":254}
2024-01-15T10:30:01Z	scan_result	{"ip":"192.168.1.1","status":"Online","response_time":1.23}
2024-01-15T10:30:02Z	process_request	{"host":"192.168.1.100","method":"WMI"}
2024-01-15T10:30:03Z	process_result	{"host":"192.168.1.100","count":45}
```

### Реализация логирования

```go
func logEvent(kind string, payload any) {
    mu.Lock()
    defer mu.Unlock()
    
    f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return
    }
    defer f.Close()
    
    data, _ := json.Marshal(payload)
    line := fmt.Sprintf("%s\t%s\t%s\n", 
        time.Now().Format(time.RFC3339), 
        kind, 
        string(data))
    
    f.WriteString(line)
}
```

## 🔒 Безопасность

### Аутентификация и авторизация

#### Текущая реализация:
- Отсутствует встроенная аутентификация
- Рекомендуется использовать reverse proxy (nginx, Apache)
- Ограничение доступа через файрвол

#### Рекомендуемые улучшения:
```go
// Middleware для базовой аутентификации
func basicAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        username, password, ok := r.BasicAuth()
        if !ok || !validateCredentials(username, password) {
            w.Header().Set("WWW-Authenticate", `Basic realm="Network Scanner"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
```

### Валидация входных данных

#### Проверка IP адресов:
```go
func isValidIP(ip string) bool {
    return net.ParseIP(ip) != nil
}

func isValidPort(port string) bool {
    p, err := strconv.Atoi(port)
    return err == nil && p > 0 && p < 65536
}
```

#### Санитизация данных:
```go
func sanitizeInput(input string) string {
    // Удаление потенциально опасных символов
    input = strings.ReplaceAll(input, "<", "&lt;")
    input = strings.ReplaceAll(input, ">", "&gt;")
    input = strings.ReplaceAll(input, "\"", "&quot;")
    input = strings.ReplaceAll(input, "'", "&#x27;")
    return input
}
```

## ⚡ Производительность

### Оптимизации

#### Ограничение горутин:
```go
const maxConcurrency = 100
semaphore := make(chan struct{}, maxConcurrency)
```

#### Буферизация каналов:
```go
results := make(chan ScanResult, len(ips))
```

#### Кэширование DNS:
```go
var dnsCache = make(map[string]string)
var dnsMutex sync.RWMutex

func getHostname(ip string) string {
    dnsMutex.RLock()
    if hostname, exists := dnsCache[ip]; exists {
        dnsMutex.RUnlock()
        return hostname
    }
    dnsMutex.RUnlock()
    
    dnsMutex.Lock()
    defer dnsMutex.Unlock()
    
    if hostname, exists := dnsCache[ip]; exists {
        return hostname
    }
    
    hostnames, err := net.LookupAddr(ip)
    if err != nil || len(hostnames) == 0 {
        dnsCache[ip] = ""
        return ""
    }
    
    hostname := hostnames[0]
    dnsCache[ip] = hostname
    return hostname
}
```

### Мониторинг производительности

#### Метрики:
- Время выполнения сканирования
- Количество активных горутин
- Использование памяти
- Количество обработанных IP адресов

#### Профилирование:
```go
import _ "net/http/pprof"

func main() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    // ... остальной код
}
```

## 🐛 Отладка

### Логирование отладки

#### Уровни логирования:
```go
const (
    DEBUG = iota
    INFO
    WARN
    ERROR
)

var logLevel = INFO

func debugLog(format string, args ...interface{}) {
    if logLevel <= DEBUG {
        log.Printf("[DEBUG] "+format, args...)
    }
}
```

### Трассировка запросов

#### Middleware для трассировки:
```go
func traceMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        traceID := generateTraceID()
        
        log.Printf("[TRACE] %s %s %s", traceID, r.Method, r.URL.Path)
        
        next(w, r)
        
        duration := time.Since(start)
        log.Printf("[TRACE] %s completed in %v", traceID, duration)
    }
}
```

## 🔄 Развертывание

### Docker

#### Dockerfile:
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
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

#### Docker Compose:
```yaml
version: '3.8'
services:
  network-scanner:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ADDR=0.0.0.0:8080
    volumes:
      - ./logs:/root/logs
```

### Kubernetes

#### Deployment:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: network-scanner
  template:
    metadata:
      labels:
        app: network-scanner
    spec:
      containers:
      - name: network-scanner
        image: network-scanner:latest
        ports:
        - containerPort: 8080
        env:
        - name: ADDR
          value: "0.0.0.0:8080"
```

Эта техническая документация предоставляет полное понимание внутренней работы Network Scanner и может быть использована для дальнейшей разработки и поддержки проекта.
