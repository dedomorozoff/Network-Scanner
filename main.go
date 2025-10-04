package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

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

type ScanStats struct {
	Total    int     `json:"total"`
	Online   int     `json:"online"`
	Offline  int     `json:"offline"`
	Errors   int     `json:"errors"`
	ScanTime float64 `json:"scan_time"`
}

type ScanPayload struct {
	Results []ScanResult `json:"results"`
	Stats   ScanStats    `json:"stats"`
}

type InterfaceInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type ProcessInfo struct {
	PID     int     `json:"PID"`
	Name    string  `json:"Name"`
	CPUP    float64 `json:"CPUP"`
	MemP    float64 `json:"MemP"`
	CmdLine string  `json:"CmdLine"`
	User    string  `json:"User"`
	Status  string  `json:"Status"`
}

var (
	logPath = filepath.Join(".", "network_scan.log")
	mu      sync.Mutex
)

func logEvent(kind string, payload any) {
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	data, _ := json.Marshal(payload)
	line := fmt.Sprintf("%s\t%s\t%s\n", time.Now().Format(time.RFC3339), kind, string(data))
	_, _ = f.WriteString(line)
}

func tailFile(path string, lines int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Читаем файл построчно и сохраняем только последние N строк
	ring := make([]string, lines)
	count := 0
	idx := 0
	scanner := bufio.NewScanner(f)
	// increase buffer for long lines
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		ring[idx%lines] = scanner.Text()
		idx++
		if count < lines {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	// Собираем последние count строк начиная с правильной позиции
	out := make([]string, 0, count)
	start := idx - count
	if start < 0 {
		start = 0
	}
	for i := 0; i < count; i++ {
		out = append(out, ring[(start+i)%lines])
	}
	return strings.Join(out, "\n"), nil
}

func parseRange(r string) []string {
	var ips []string
	if r == "" {
		return ips
	}
	if m := strings.Split(r, "-"); len(m) == 2 {
		if strings.Count(m[0], ".") == 3 && strings.Count(m[1], ".") == 0 {
			base := strings.Split(m[0], ".")
			start, _ := strconv.Atoi(base[3])
			end, _ := strconv.Atoi(m[1])
			for i := start; i <= end; i++ {
				ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", base[0], base[1], base[2], i))
			}
			return ips
		}
		if strings.Count(m[0], ".") == 3 && strings.Count(m[1], ".") == 3 {
			start := strings.Split(m[0], ".")
			end := strings.Split(m[1], ".")
			for a := atoi(start[0]); a <= atoi(end[0]); a++ {
				for b := atoi(start[1]); b <= atoi(end[1]); b++ {
					for c := atoi(start[2]); c <= atoi(end[2]); c++ {
						for d := atoi(start[3]); d <= atoi(end[3]); d++ {
							ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
						}
					}
				}
			}
		}
	}
	return ips
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func pingHost(ctx context.Context, ip string, timeoutMs int, sourceIP string) ScanResult {
	start := time.Now()
	isWindows := runtime.GOOS == "windows"
	isBSD := runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "darwin"
	var cmd *exec.Cmd
	if isWindows {
		args := []string{"-n", "1", "-w", strconv.Itoa(timeoutMs)}
		if sourceIP != "" {
			args = append(args, "-S", sourceIP)
		}
		args = append(args, ip)
		cmd = exec.CommandContext(ctx, "ping", args...)
	} else if isBSD {
		// BSD ping: -c count, -W wait (seconds), source via -S addr
		sec := int(math.Max(1, math.Ceil(float64(timeoutMs)/1000)))
		args := []string{"-c", "1", "-W", strconv.Itoa(sec)}
		if sourceIP != "" {
			args = append(args, "-S", sourceIP)
		}
		args = append(args, ip)
		cmd = exec.CommandContext(ctx, "ping", args...)
	} else {
		// Linux
		sec := int(math.Max(1, math.Ceil(float64(timeoutMs)/1000)))
		args := []string{"-c", "1", "-W", strconv.Itoa(sec)}
		if sourceIP != "" {
			args = append(args, "-I", sourceIP)
		}
		args = append(args, ip)
		cmd = exec.CommandContext(ctx, "ping", args...)
	}
	_ = cmd.Run()
	dur := time.Since(start).Seconds() * 1000
	status := "offline"
	var rt float64
	if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
		status = "online"
		rt = math.Round(dur*100) / 100
	}
	return ScanResult{IP: ip, Status: status, ResponseTime: rt, Timestamp: time.Now().Format("2006-01-02 15:04:05")}
}

func resolveHostname(ctx context.Context, ip string) string {
	// Try reverse DNS with a short timeout to avoid blocking long
	if net.ParseIP(ip) == nil {
		return "Unknown"
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return "Unknown"
	}
	// Trim trailing dot from FQDN if present
	return strings.TrimSuffix(names[0], ".")
}

func getProcessesFromComputer(ip string) map[string]interface{} {
	isWindows := runtime.GOOS == "windows"
	var cmd *exec.Cmd

	if isWindows {
		// Упрощенная команда PowerShell для получения процессов
		// Предлагаем два варианта: WMI и альтернативный метод
		// Используем исправленный PowerShell скрипт

		// Используем рабочий PowerShell скрипт для получения процессов
		cmd = exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", "fix.ps1", "-ComputerName", ip)
	} else {
		// Linux/Unix: используем ssh с ps aux
		cmd = exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip),
			"ps aux --no-headers | awk '{print $2 \"|\" $11 \"|\" $3 \"|\" $4 \"|\" $1 \"|\" $8}'")
	}

	output, err := cmd.Output()
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Не удалось получить список процессов с %s: %v", ip, err),
		}
	}

	if isWindows {
		// Парсим JSON ответ от PowerShell скрипта
		outputStr := strings.TrimSpace(string(output))

		// Удаляем все символы управления кроме разрешенных
		var cleanedStr strings.Builder
		for _, r := range outputStr {
			// Разрешенные символы: printable ASCII (32-126), табуляция (9), новая строка (10), возврат каретки (13)
			if r >= 32 && r <= 126 || r == '\n' || r == '\r' || r == '\t' {
				cleanedStr.WriteRune(r)
			}
		}
		outputStr = cleanedStr.String()

		// Удаляем возможные пробелы в начале и конце
		outputStr = strings.TrimSpace(outputStr)

		// Проверяем, что у нас есть валидный JSON
		if outputStr == "" {
			return map[string]interface{}{
				"success": false,
				"error":   "PowerShell script returned empty output",
			}
		}

		// Проверяем, содержит ли вывод ошибку
		if strings.Contains(outputStr, `"error"`) || strings.Contains(outputStr, `"success"`) {
			var errorResult map[string]interface{}
			if err := json.Unmarshal([]byte(outputStr), &errorResult); err == nil {
				return errorResult
			}
		}

		// Парсим успешный список процессов
		var processes []ProcessInfo
		if err := json.Unmarshal([]byte(outputStr), &processes); err != nil {
			// Добавляем отладочную информацию
			return map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Failed to parse processes JSON: %v", err),
				"debug":   fmt.Sprintf("Output length: %d chars, first 200 chars: %s", len(outputStr), truncateString(outputStr, 200)),
			}
		}

		return map[string]interface{}{
			"success":   true,
			"processes": processes,
			"platform":  "windows",
		}
	} else {
		// Парсим вывод ps aux для Linux
		var processes []ProcessInfo
		lines := strings.Split(string(output), "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Split(line, "|")
			if len(parts) >= 6 {
				if pid, err := strconv.Atoi(parts[0]); err == nil && pid > 0 {
					cpu, _ := strconv.ParseFloat(parts[2], 64)
					mem, _ := strconv.ParseFloat(parts[3], 64)

					processes = append(processes, ProcessInfo{
						PID:     pid,
						Name:    filepath.Base(parts[1]), // Получаем имя процесса из пути
						CPUP:    cpu,
						MemP:    mem,
						CmdLine: parts[1],
						User:    parts[4],
						Status:  parts[5],
					})
				}
			}
		}

		return map[string]interface{}{
			"success":   true,
			"processes": processes,
			"platform":  "linux",
		}
	}
}

func killProcessOnComputer(ip string, pid int, processName string) map[string]interface{} {
	isWindows := runtime.GOOS == "windows"

	if isWindows {
		// Windows: используем PowerShell для удаленного выполнения
		// Сначала попробуем через WMI
		cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile",
			"-Command", fmt.Sprintf("try { Invoke-WmiMethod -Class Win32_Process -Name Terminate -ArgumentList %d -ComputerName %s -ErrorAction Stop; Write-Host 'SUCCESS' } catch { Write-Host 'ERROR:' $_.Exception.Message }", pid, ip))
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "SUCCESS") {
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Процесс %s (PID: %d) успешно завершен через WMI", processName, pid),
			}
		}

		// Попробуем через PowerShell Remoting
		psCmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile",
			"-Command", fmt.Sprintf("try { Invoke-Command -ComputerName %s -ScriptBlock { Stop-Process -Id %d -Force -ErrorAction Stop } -ErrorAction Stop; Write-Host 'SUCCESS' } catch { Write-Host 'ERROR:' $_.Exception.Message }", ip, pid))
		psOutput, psErr := psCmd.Output()
		if psErr == nil && strings.Contains(string(psOutput), "SUCCESS") {
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Процесс %s (PID: %d) завершен через PowerShell Remoting", processName, pid),
			}
		}

		// Попробуем через wmic как альтернативу
		wmicCmd := exec.Command("wmic", "/node:"+ip, "process", "where", fmt.Sprintf("ProcessId=%d", pid), "delete")
		wmicOutput, wmicErr := wmicCmd.Output()
		if wmicErr == nil && !strings.Contains(string(wmicOutput), "No Instance(s) Available") {
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Процесс %s (PID: %d) завершен через WMIC", processName, pid),
			}
		}

		// Собираем детальную информацию об ошибках
		var errorDetails []string
		if err != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("WMI: %v", err))
		}
		if psErr != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("PowerShell Remoting: %v", psErr))
		}
		if wmicErr != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("WMIC: %v", wmicErr))
		}

		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Не удалось завершить процесс %s (PID: %d) на %s. Возможные причины: отсутствие прав доступа, процесс уже завершен, или удаленный компьютер недоступен. Детали ошибок: %s", processName, pid, ip, strings.Join(errorDetails, "; ")),
		}
	} else {
		// Linux/Unix: используем ssh с kill
		cmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip), fmt.Sprintf("kill -9 %d", pid))
		err := cmd.Run()
		if err == nil {
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Процесс %s (PID: %d) успешно завершен", processName, pid),
			}
		}

		// Попробуем через rsh
		rshCmd := exec.Command("rsh", ip, fmt.Sprintf("kill -9 %d", pid))
		rshErr := rshCmd.Run()
		if rshErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Процесс %s (PID: %d) завершен через RSH", processName, pid),
			}
		}

		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Не удалось завершить процесс %s (PID: %d) на %s. Возможные причины: отсутствие SSH доступа, процесс уже завершен, или недостаточно прав. Ошибки: SSH=%v, RSH=%v", processName, pid, ip, err, rshErr),
		}
	}
}

func shutdownComputer(ip string) map[string]interface{} {
	isWindows := runtime.GOOS == "windows"

	if isWindows {
		// Windows: используем PowerShell Stop-Computer
		cmd := exec.Command("powershell", "-Command", "Stop-Computer -ComputerName "+ip+" -Force -Confirm:$false")
		err := cmd.Run()
		if err == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Команда выключения отправлена успешно",
			}
		}

		// Попробуем через shutdown.exe как резервный метод
		shutdownCmd := exec.Command("shutdown", "/s", "/m", "\\\\"+ip, "/t", "10", "/c", "Выключение по команде Network Scanner")
		shutdownErr := shutdownCmd.Run()
		if shutdownErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Команда выключения отправлена через shutdown.exe",
			}
		}
	} else {
		// Linux/Unix: используем ssh с sudo shutdown
		cmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "root@"+ip, "sudo shutdown -h +1 \"Выключение по команде Network Scanner\"")
		err := cmd.Run()
		if err == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Команда выключения отправлена успешно",
			}
		}

		// Попробуем через rsh
		rshCmd := exec.Command("rsh", ip, "sudo shutdown -h +1")
		rshErr := rshCmd.Run()
		if rshErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Команда выключения отправлена через RSH",
			}
		}
	}

	return map[string]interface{}{
		"success": false,
		"error":   "Не удалось отправить команду выключения. Возможно, требуется настройка удаленного управления или отсутствуют права доступа.",
	}
}

func sendMessageToComputer(ip string, message string) map[string]interface{} {
	isWindows := runtime.GOOS == "windows"

	if isWindows {
		// Windows: используем msg.exe для отправки сообщений
		// Сначала попробуем отправить всем пользователям
		cmd := exec.Command("msg", "*", "/SERVER:"+ip, message)
		err := cmd.Run()
		if err == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено всем пользователям на " + ip,
			}
		}

		// Попробуем через PowerShell с Send-MailMessage (если настроен SMTP)
		psCmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-NoProfile",
			"-Command", fmt.Sprintf("try { Invoke-Command -ComputerName %s -ScriptBlock { Write-Host '%s' -ForegroundColor Yellow } -ErrorAction Stop; Write-Host 'SUCCESS' } catch { Write-Host 'ERROR:' $_.Exception.Message }", ip, message))
		psOutput, psErr := psCmd.Output()
		if psErr == nil && strings.Contains(string(psOutput), "SUCCESS") {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через PowerShell на " + ip,
			}
		}

		// Попробуем через net send (если доступен)
		netCmd := exec.Command("net", "send", ip, message)
		netOutput, netErr := netCmd.Output()
		if netErr == nil && !strings.Contains(string(netOutput), "error") {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через net send на " + ip,
			}
		}

		// Попробуем через WMIC
		wmicCmd := exec.Command("wmic", "/node:"+ip, "process", "call", "create", fmt.Sprintf("cmd /c echo %s", message))
		wmicOutput, wmicErr := wmicCmd.Output()
		if wmicErr == nil && !strings.Contains(string(wmicOutput), "No Instance(s) Available") {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через WMIC на " + ip,
			}
		}

		// Собираем детальную информацию об ошибках
		var errorDetails []string
		// err уже проверен выше, добавляем информацию о том, что msg не сработал
		errorDetails = append(errorDetails, "msg: команда не выполнена")
		if psErr != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("PowerShell: %v", psErr))
		}
		if netErr != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("net send: %v", netErr))
		}
		if wmicErr != nil {
			errorDetails = append(errorDetails, fmt.Sprintf("WMIC: %v", wmicErr))
		}

		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Не удалось отправить сообщение на %s. Возможные причины: отсутствие прав доступа, служба Messenger отключена, или удаленный компьютер недоступен. Детали ошибок: %s", ip, strings.Join(errorDetails, "; ")),
		}
	} else {
		// Linux/Unix: используем различные методы отправки сообщений

		// Попробуем через wall (write all)
		wallCmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip), fmt.Sprintf("echo '%s' | wall", message))
		err := wallCmd.Run()
		if err == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через wall на " + ip,
			}
		}

		// Попробуем через write для конкретного пользователя
		writeCmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip), fmt.Sprintf("who | awk '{print $1}' | head -1 | xargs -I {} write {} '%s'", message))
		writeErr := writeCmd.Run()
		if writeErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через write на " + ip,
			}
		}

		// Попробуем через notify-send (если доступен)
		notifyCmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip), fmt.Sprintf("DISPLAY=:0 notify-send 'Network Scanner' '%s'", message))
		notifyErr := notifyCmd.Run()
		if notifyErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через notify-send на " + ip,
			}
		}

		// Попробуем через rsh
		rshCmd := exec.Command("rsh", ip, fmt.Sprintf("echo '%s' | wall", message))
		rshErr := rshCmd.Run()
		if rshErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через RSH на " + ip,
			}
		}

		// Попробуем через echo в терминал
		echoCmd := exec.Command("ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
			fmt.Sprintf("root@%s", ip), fmt.Sprintf("echo '%s' > /dev/tty", message))
		echoErr := echoCmd.Run()
		if echoErr == nil {
			return map[string]interface{}{
				"success": true,
				"message": "Сообщение отправлено через echo на " + ip,
			}
		}

		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Не удалось отправить сообщение на %s. Возможные причины: отсутствие SSH доступа, отсутствие активных пользователей, или недостаточно прав. Ошибки: wall=%v, write=%v, notify-send=%v, rsh=%v, echo=%v", ip, err, writeErr, notifyErr, rshErr, echoErr),
		}
	}
}

// WebSocket upgrader для VNC прокси
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем все origin для локального использования
	},
}

// VNC WebSocket прокси
func vncProxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("VNC Proxy: получен запрос %s %s", r.Method, r.URL.String())

	// Проверяем, что это WebSocket запрос
	if !websocket.IsWebSocketUpgrade(r) {
		log.Printf("VNC Proxy: не WebSocket запрос, заголовки: %v", r.Header)
		http.Error(w, "Требуется WebSocket соединение", http.StatusBadRequest)
		return
	}

	// Получаем параметры VNC сервера из query
	vncHost := r.URL.Query().Get("host")
	vncPort := r.URL.Query().Get("port")

	if vncHost == "" {
		vncHost = "localhost"
	}
	if vncPort == "" {
		vncPort = "5900"
	}

	log.Printf("VNC Proxy: подключение к %s:%s", vncHost, vncPort)

	// Обновляем HTTP соединение до WebSocket
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("VNC Proxy: ошибка обновления до WebSocket: %v", err)
		return
	}
	defer wsConn.Close()
	log.Printf("VNC Proxy: WebSocket соединение установлено")

	// Подключаемся к VNC серверу после успешного WebSocket соединения
	vncAddr := net.JoinHostPort(vncHost, vncPort)
	vncConn, err := net.Dial("tcp", vncAddr)
	if err != nil {
		log.Printf("Не удалось подключиться к VNC серверу %s: %v", vncAddr, err)
		wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "Не удалось подключиться к VNC серверу"))
		return
	}
	defer vncConn.Close()

	// Канал для завершения
	done := make(chan struct{})
	var once sync.Once

	// Копируем данные от VNC сервера к WebSocket клиенту
	go func() {
		defer once.Do(func() { close(done) })
		buffer := make([]byte, 4096)
		for {
			n, err := vncConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("VNC Proxy: ошибка чтения от VNC: %v", err)
				}
				break
			}
			err = wsConn.WriteMessage(websocket.BinaryMessage, buffer[:n])
			if err != nil {
				log.Printf("VNC Proxy: ошибка записи в WebSocket: %v", err)
				break
			}
		}
	}()

	// Копируем данные от WebSocket клиента к VNC серверу
	go func() {
		defer once.Do(func() { close(done) })
		for {
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("VNC Proxy: ошибка чтения из WebSocket: %v", err)
				}
				break
			}
			_, err = vncConn.Write(message)
			if err != nil {
				log.Printf("VNC Proxy: ошибка записи в VNC: %v", err)
				break
			}
		}
	}()

	// Ждем завершения одной из горутин
	<-done
	log.Printf("VNC Proxy: соединение завершено")
}

func listInterfaces() []InterfaceInfo {
	isWindows := runtime.GOOS == "windows"
	isBSD := runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "darwin"
	var out []byte
	var err error
	if isWindows {
		out, err = exec.Command("ipconfig").Output()
		if err != nil {
			return nil
		}
		s := bufio.NewScanner(bytes.NewReader(out))
		var name string
		var res []InterfaceInfo
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" {
				continue
			}
			if strings.HasSuffix(line, ":") && (strings.Contains(strings.ToLower(line), "adapter") || strings.Contains(strings.ToLower(line), "адаптер")) {
				name = strings.TrimSuffix(strings.TrimSpace(line), ":")
				continue
			}
			if strings.Contains(strings.ToLower(line), "ipv4") && strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					ip := strings.TrimSpace(parts[len(parts)-1])
					if ip != "127.0.0.1" {
						res = append(res, InterfaceInfo{Name: name, IP: ip})
					}
				}
			}
		}
		return res
	}
	if isBSD {
		out, err = exec.Command("ifconfig", "-a", "inet").Output()
		if err != nil {
			return nil
		}
		s := bufio.NewScanner(bytes.NewReader(out))
		var current string
		var res []InterfaceInfo
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "inet ") && !strings.HasPrefix(line, "inet6 ") && !strings.HasPrefix(line, "\tinet ") {
				// likely interface header like: em0: flags=...
				if strings.Contains(line, ":") {
					current = strings.TrimSuffix(strings.Fields(line)[0], ":")
				}
				continue
			}
			if strings.HasPrefix(line, "inet ") || strings.HasPrefix(line, "\tinet ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					ip := parts[1]
					if ip != "127.0.0.1" {
						res = append(res, InterfaceInfo{Name: current, IP: ip})
					}
				}
			}
		}
		return res
	}
	out, err = exec.Command("sh", "-lc", "ip -4 -o addr").Output()
	if err != nil {
		return nil
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	var res []InterfaceInfo
	for s.Scan() {
		line := s.Text()
		// 2: eth0    inet 192.168.1.10/24 ...
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == "inet" {
			ip := strings.Split(fields[3], "/")[0]
			if ip != "127.0.0.1" {
				res = append(res, InterfaceInfo{Name: fields[1], IP: ip})
			}
		}
	}
	return res
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery == "" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, indexHTML)
		return
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "interfaces":
			json.NewEncoder(w).Encode(map[string]any{"interfaces": listInterfaces()})
			return
		case "scan":
			networkRange := r.FormValue("network_range")
			timeout, _ := strconv.Atoi(r.FormValue("timeout"))
			showOffline := r.FormValue("show_offline") != ""
			sourceIP := r.FormValue("source_ip")
			payload := runScan(networkRange, timeout, sourceIP)
			if !showOffline {
				filtered := make([]ScanResult, 0, len(payload.Results))
				for _, it := range payload.Results {
					if it.Status == "online" {
						filtered = append(filtered, it)
					}
				}
				payload.Results = filtered
			}
			json.NewEncoder(w).Encode(payload)
			return
		case "export":
			var data ScanPayload
			_ = json.Unmarshal([]byte(r.FormValue("data")), &data)
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=network_scan_%s.csv", time.Now().Format("2006-01-02_15-04-05")))
			cw := csv.NewWriter(w)
			_ = cw.Write([]string{"IP Address", "Status", "Response Time (ms)", "Hostname", "Timestamp"})
			for _, it := range data.Results {
				_ = cw.Write([]string{it.IP, it.Status, fmt.Sprintf("%v", it.ResponseTime), it.Hostname, it.Timestamp})
			}
			cw.Flush()
			return
		case "log_tail":
			lines, _ := strconv.Atoi(r.FormValue("lines"))
			if lines <= 0 {
				lines = 200
			}
			text, _ := tailFile(logPath, lines)
			json.NewEncoder(w).Encode(map[string]string{"text": text})
			return
		case "log_download":
			http.ServeFile(w, r, logPath)
			return
		case "shutdown":
			ip := r.FormValue("ip")
			if ip == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "IP адрес не указан"})
				return
			}

			result := shutdownComputer(ip)
			if result["success"].(bool) {
				logEvent("SHUTDOWN_SUCCESS", map[string]interface{}{"ip": ip, "message": result["message"]})
			} else {
				logEvent("SHUTDOWN_ERROR", map[string]interface{}{"ip": ip, "error": result["error"]})
			}
			json.NewEncoder(w).Encode(result)
			return
		case "processes":
			ip := r.FormValue("ip")
			if ip == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "IP адрес не указан"})
				return
			}

			// Сначала проверяем, что компьютер онлайн
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			res := pingHost(ctx, ip, 2000, "")
			if res.Status != "online" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   fmt.Sprintf("Компьютер %s недоступен. Статус: %s", ip, res.Status),
				})
				return
			}

			result := getProcessesFromComputer(ip)
			if result["success"].(bool) {
				logEvent("PROCESSES_SUCCESS", map[string]interface{}{"ip": ip, "count": len(result["processes"].([]ProcessInfo))})
			} else {
				logEvent("PROCESSES_ERROR", map[string]interface{}{"ip": ip, "error": result["error"]})
			}
			json.NewEncoder(w).Encode(result)
			return
		case "kill_process":
			ip := r.FormValue("ip")
			pidStr := r.FormValue("pid")
			processName := r.FormValue("process_name")

			if ip == "" || pidStr == "" || processName == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Не все параметры указаны"})
				return
			}

			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Неверный PID процесса"})
				return
			}

			// Сначала проверяем, что компьютер онлайн
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			res := pingHost(ctx, ip, 2000, "")
			if res.Status != "online" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   fmt.Sprintf("Компьютер %s недоступен. Статус: %s", ip, res.Status),
				})
				return
			}

			result := killProcessOnComputer(ip, pid, processName)
			if result["success"].(bool) {
				logEvent("KILL_PROCESS_SUCCESS", map[string]interface{}{"ip": ip, "pid": pid, "process_name": processName, "message": result["message"]})
			} else {
				logEvent("KILL_PROCESS_ERROR", map[string]interface{}{"ip": ip, "pid": pid, "process_name": processName, "error": result["error"]})
			}
			json.NewEncoder(w).Encode(result)
			return
		case "send_message":
			ip := r.FormValue("ip")
			message := r.FormValue("message")

			if ip == "" || message == "" {
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "IP адрес и сообщение обязательны"})
				return
			}

			// Сначала проверяем, что компьютер онлайн
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			res := pingHost(ctx, ip, 2000, "")
			if res.Status != "online" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"error":   fmt.Sprintf("Компьютер %s недоступен. Статус: %s", ip, res.Status),
				})
				return
			}

			result := sendMessageToComputer(ip, message)
			if result["success"].(bool) {
				logEvent("SEND_MESSAGE_SUCCESS", map[string]interface{}{"ip": ip, "message": message, "result_message": result["message"]})
			} else {
				logEvent("SEND_MESSAGE_ERROR", map[string]interface{}{"ip": ip, "message": message, "error": result["error"]})
			}
			json.NewEncoder(w).Encode(result)
			return
		}
	}

	if r.Method == http.MethodGet && r.URL.Query().Get("action") == "scan_stream" {
		scanStream(w, r)
		return
	}

	http.NotFound(w, r)
}

func runScan(networkRange string, timeout int, sourceIP string) ScanPayload {
	ips := parseRange(networkRange)
	if len(ips) == 0 {
		return ScanPayload{Results: nil, Stats: ScanStats{}}
	}
	start := time.Now()
	results := make([]ScanResult, 0, len(ips))
	var online, offline, errs int
	logEvent("START", map[string]any{"range": networkRange, "timeout": timeout, "source_ip": sourceIP})
	for i, ip := range ips {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+500)*time.Millisecond)
		res := pingHost(ctx, ip, timeout, sourceIP)
		cancel()
		res.Index = i + 1
		res.Total = len(ips)
		res.Progress = math.Round(float64(i+1)/float64(len(ips))*10000) / 100
		if res.Status == "online" {
			// Resolve hostname for online hosts
			hostCtx, hostCancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			res.Hostname = resolveHostname(hostCtx, ip)
			hostCancel()
			online++
		} else if res.Status == "offline" {
			res.Hostname = "N/A"
			offline++
		} else {
			res.Hostname = "N/A"
			errs++
		}
		results = append(results, res)
		logEvent("ENTRY", res)
	}
	stats := ScanStats{Total: len(ips), Online: online, Offline: offline, Errors: errs, ScanTime: math.Round(time.Since(start).Seconds()*100) / 100}
	logEvent("DONE", stats)
	return ScanPayload{Results: results, Stats: stats}
}

func scanStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	networkRange := r.URL.Query().Get("network_range")
	timeout, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
	showOffline := r.URL.Query().Get("show_offline") == "1"
	sourceIP := r.URL.Query().Get("source_ip")

	ips := parseRange(networkRange)
	logEvent("START", map[string]any{"range": networkRange, "timeout": timeout, "source_ip": sourceIP, "stream": true})
	if len(ips) == 0 {
		fmt.Fprintf(w, "event: error\n")
		fmt.Fprintf(w, "data: %s\n\n", toJSON(map[string]string{"error": "Неверный формат диапазона IP адресов"}))
		flusher.Flush()
		return
	}

	start := time.Now()
	var online, offline, errs int
	results := make([]ScanResult, 0, len(ips))
	ctx := r.Context()
forLoop:
	for i, ip := range ips {
		select {
		case <-ctx.Done():
			// Client disconnected or requested stop; finish early
			break forLoop
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+500)*time.Millisecond)
		res := pingHost(ctx, ip, timeout, sourceIP)
		cancel()
		res.Index = i + 1
		res.Total = len(ips)
		res.Progress = math.Round(float64(i+1)/float64(len(ips))*10000) / 100
		if res.Status == "online" {
			// Resolve hostname for online hosts
			hostCtx, hostCancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
			res.Hostname = resolveHostname(hostCtx, ip)
			hostCancel()
			online++
		} else if res.Status == "offline" {
			res.Hostname = "N/A"
			offline++
		} else {
			res.Hostname = "N/A"
			errs++
		}
		results = append(results, res)
		logEvent("ENTRY", res)

		// Применяем фильтрацию offline компьютеров только если showOffline = false
		if !showOffline && res.Status != "online" {
			fmt.Fprintf(w, "event: progress\n")
			fmt.Fprintf(w, "data: %s\n\n", toJSON(map[string]any{
				"progress": res.Progress,
				"index":    res.Index,
				"total":    res.Total,
				"counts":   map[string]int{"online": online, "offline": offline, "errors": errs},
				"result":   nil,
			}))
			flusher.Flush()
			continue
		}

		fmt.Fprintf(w, "event: progress\n")
		fmt.Fprintf(w, "data: %s\n\n", toJSON(map[string]any{
			"progress": res.Progress,
			"index":    res.Index,
			"total":    res.Total,
			"counts":   map[string]int{"online": online, "offline": offline, "errors": errs},
			"result":   res,
		}))
		flusher.Flush()
	}
	stats := ScanStats{Total: len(ips), Online: online, Offline: offline, Errors: errs, ScanTime: math.Round(time.Since(start).Seconds()*100) / 100}
	logEvent("DONE", stats)

	// Применяем фильтрацию offline компьютеров к финальным результатам
	finalResults := results
	if !showOffline {
		filtered := make([]ScanResult, 0, len(results))
		for _, it := range results {
			if it.Status == "online" {
				filtered = append(filtered, it)
			}
		}
		finalResults = filtered
	}

	payload := ScanPayload{Results: finalResults, Stats: stats}
	fmt.Fprintf(w, "event: done\n")
	fmt.Fprintf(w, "data: %s\n\n", toJSON(payload))
	flusher.Flush()
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func handleNoVNC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, noVNCHTML)
}

func handleVNCClient(w http.ResponseWriter, r *http.Request) {
	// Читаем содержимое файла vnc_client.html
	content, err := os.ReadFile("vnc_client.html")
	if err != nil {
		http.Error(w, "Файл vnc_client.html не найден", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/novnc", handleNoVNC)
	http.HandleFunc("/vnc_client.html", handleVNCClient)
	http.HandleFunc("/websockify", vncProxyHandler)

	// Статические файлы для noVNC
	http.Handle("/novnc/", http.StripPrefix("/novnc/", http.FileServer(http.Dir("novnc/"))))

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	log.Printf("Server started at http://%s (listening on all interfaces)\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

const noVNCHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>noVNC - VNC клиент</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            min-height: 100vh; 
            display: flex; 
            flex-direction: column; 
        }
        .header { 
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); 
            color: white; 
            padding: 20px; 
            text-align: center; 
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .controls { 
            background: white; 
            padding: 20px; 
            border-radius: 10px; 
            margin: 20px; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); 
        }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; color: #333; }
        .form-group input { 
            width: 100%; 
            padding: 10px; 
            border: 2px solid #e1e5e9; 
            border-radius: 5px; 
            font-size: 16px; 
        }
        .btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 5px; 
            font-size: 16px; 
            font-weight: 600; 
            cursor: pointer; 
            margin-right: 10px; 
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .btn-danger { background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%); }
        .vnc-container { 
            flex: 1; 
            margin: 20px; 
            background: white; 
            border-radius: 10px; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.1); 
            overflow: hidden; 
            display: flex; 
            flex-direction: column; 
        }
        .vnc-header { 
            background: #f8f9fa; 
            padding: 15px 20px; 
            border-bottom: 2px solid #e1e5e9; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        .vnc-canvas { 
            flex: 1; 
            background: #000; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            color: white; 
            font-size: 18px; 
        }
        .status { 
            padding: 10px 20px; 
            background: #f8f9fa; 
            border-top: 1px solid #e1e5e9; 
            font-size: 14px; 
            color: #666; 
        }
        .status.connected { background: #d4edda; color: #155724; }
        .status.disconnected { background: #f8d7da; color: #721c24; }
        .status.connecting { background: #fff3cd; color: #856404; }
        #noVNC_canvas { 
            max-width: 100%; 
            max-height: 100%; 
            border: none; 
        }
        .loading { text-align: center; padding: 40px; }
        .error { 
            background: #f8d7da; 
            color: #721c24; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 10px 0; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ noVNC - Веб VNC клиент</h1>
        <p>Подключение к удаленному рабочему столу через браузер</p>
    </div>
    
    <div class="controls">
        <div class="form-group">
            <label for="vncHost">VNC сервер (IP адрес):</label>
            <input type="text" id="vncHost" placeholder="192.168.1.100" value="">
        </div>
        <div class="form-group">
            <label for="vncPort">Порт VNC:</label>
            <input type="number" id="vncPort" placeholder="5900" value="5900">
        </div>
        <div class="form-group">
            <label for="vncPassword">Пароль VNC (если требуется):</label>
            <input type="password" id="vncPassword" placeholder="Оставьте пустым, если пароль не требуется">
        </div>
        <button class="btn" id="connectBtn" onclick="connectVNC()">🔗 Подключиться</button>
        <button class="btn btn-danger" id="disconnectBtn" onclick="disconnectVNC()" disabled>❌ Отключиться</button>
    </div>
    
    <div class="vnc-container">
        <div class="vnc-header">
            <div>
                <strong>VNC подключение:</strong> <span id="connectionInfo">Не подключено</span>
            </div>
            <div>
                <button class="btn" onclick="toggleFullscreen()" id="fullscreenBtn">⛶ Полный экран</button>
            </div>
        </div>
        <div class="vnc-canvas" id="vncCanvas">
            <div class="loading" id="loadingMessage">
                <div>🖥️ Готов к подключению</div>
                <div style="font-size: 14px; margin-top: 10px; opacity: 0.7;">
                    Введите данные VNC сервера и нажмите "Подключиться"
                </div>
            </div>
        </div>
        <div class="status" id="statusBar">
            Статус: Ожидание подключения
        </div>
    </div>

    <!-- noVNC библиотеки -->
    <script src="https://cdn.jsdelivr.net/npm/novnc@1.4.0/lib/novnc.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/webrtc-adapter@8.2.3/adapter.min.js"></script>
    
    <script>
        let rfb = null;
        let isConnected = false;
        
        // Получаем параметры из URL
        const urlParams = new URLSearchParams(window.location.search);
        const host = urlParams.get('host');
        const port = urlParams.get('port') || '5900';
        const password = urlParams.get('password') || '';
        
        // Заполняем форму, если параметры переданы
        if (host) {
            document.getElementById('vncHost').value = host;
            document.getElementById('vncPort').value = port;
            document.getElementById('vncPassword').value = password;
        }
        
        function connectVNC() {
            const host = document.getElementById('vncHost').value.trim();
            const port = document.getElementById('vncPort').value.trim();
            const password = document.getElementById('vncPassword').value;
            
            if (!host) {
                showError('Введите IP адрес VNC сервера');
                return;
            }
            
            if (isConnected) {
                disconnectVNC();
                return;
            }
            
            setStatus('connecting', 'Подключение к ' + host + ':' + port + '...');
            document.getElementById('connectBtn').disabled = true;
            document.getElementById('disconnectBtn').disabled = false;
            
            const url = 'ws://' + host + ':' + port;
            const canvas = document.getElementById('vncCanvas');
            
            // Очищаем canvas
            canvas.innerHTML = '';
            
            try {
                rfb = new RFB(canvas, url, {
                    credentials: { password: password }
                });
                
                rfb.addEventListener('connect', onConnect);
                rfb.addEventListener('disconnect', onDisconnect);
                rfb.addEventListener('credentialsrequired', onCredentialsRequired);
                rfb.addEventListener('securityfailure', onSecurityFailure);
                rfb.addEventListener('clipboard', onClipboard);
                
            } catch (error) {
                showError('Ошибка подключения: ' + error.message);
                setStatus('disconnected', 'Ошибка подключения');
                document.getElementById('connectBtn').disabled = false;
                document.getElementById('disconnectBtn').disabled = true;
            }
        }
        
        function disconnectVNC() {
            if (rfb) {
                rfb.disconnect();
                rfb = null;
            }
            isConnected = false;
            setStatus('disconnected', 'Отключено');
            document.getElementById('connectBtn').disabled = false;
            document.getElementById('disconnectBtn').disabled = true;
            document.getElementById('connectionInfo').textContent = 'Не подключено';
            
            // Показываем сообщение о готовности
            const canvas = document.getElementById('vncCanvas');
            canvas.innerHTML = '<div class="loading"><div>Готов к подключению</div><div style="font-size: 14px; margin-top: 10px; opacity: 0.7;">Введите данные VNC сервера и нажмите "Подключиться"</div></div>';
        }
        
        function onConnect() {
            isConnected = true;
            setStatus('connected', 'Подключено к ' + document.getElementById('vncHost').value + ':' + document.getElementById('vncPort').value);
            document.getElementById('connectionInfo').textContent = document.getElementById('vncHost').value + ':' + document.getElementById('vncPort').value;
            document.getElementById('connectBtn').textContent = '🔗 Переподключиться';
        }
        
        function onDisconnect(e) {
            isConnected = false;
            if (e.detail.clean) {
                setStatus('disconnected', 'Отключено');
            } else {
                setStatus('disconnected', 'Соединение потеряно');
                showError('Соединение потеряно: ' + (e.detail.reason || 'Неизвестная причина'));
            }
            document.getElementById('connectBtn').disabled = false;
            document.getElementById('disconnectBtn').disabled = true;
            document.getElementById('connectBtn').textContent = '🔗 Подключиться';
        }
        
        function onCredentialsRequired(e) {
            const password = document.getElementById('vncPassword').value;
            if (password) {
                rfb.sendCredentials({ password: password });
            } else {
                showError('Требуется пароль VNC');
                disconnectVNC();
            }
        }
        
        function onSecurityFailure(e) {
            showError('Ошибка безопасности: ' + (e.detail.reason || 'Неизвестная ошибка'));
            disconnectVNC();
        }
        
        function onClipboard(e) {
            // Обработка буфера обмена
            console.log('Clipboard data:', e.detail.text);
        }
        
        function setStatus(type, message) {
            const statusBar = document.getElementById('statusBar');
            statusBar.className = 'status ' + type;
            statusBar.textContent = 'Статус: ' + message;
        }
        
        function showError(message) {
            const canvas = document.getElementById('vncCanvas');
            canvas.innerHTML = '<div class="error"><strong>Ошибка:</strong> ' + message + '</div>';
        }
        
        function toggleFullscreen() {
            const canvas = document.getElementById('vncCanvas');
            if (!document.fullscreenElement) {
                canvas.requestFullscreen().catch(err => {
                    console.log('Ошибка входа в полноэкранный режим:', err);
                });
            } else {
                document.exitFullscreen();
            }
        }
        
        // Обработка клавиш
        document.addEventListener('keydown', function(e) {
            if (isConnected && rfb) {
                // Передаем клавиши в VNC
                if (e.key === 'F11') {
                    e.preventDefault();
                    toggleFullscreen();
                }
            }
        });
        
        // Автоматическое подключение, если параметры переданы
        if (host) {
            setTimeout(() => {
                connectVNC();
            }, 1000);
        }
    </script>
</body>
</html>`

const indexHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner - Веб-интерфейс</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height:100vh; padding:20px; }
        .container { max-width:1200px; margin:0 auto; background:white; border-radius:15px; box-shadow:0 20px 40px rgba(0,0,0,0.1); overflow:hidden; }
        .header { background:linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color:white; padding:30px; text-align:center; }
        .header h1 { font-size:2.5em; margin-bottom:10px; }
        .header p { font-size:1.1em; opacity:0.9; }
        .content { padding:30px; }
        .form-section { background:#f8f9fa; border-radius:10px; padding:25px; margin-bottom:30px; }
        .form-group { margin-bottom:20px; }
        .form-group label { display:block; margin-bottom:8px; font-weight:600; color:#333; }
        .form-group input, .form-group select { width:100%; padding:12px; border:2px solid #e1e5e9; border-radius:8px; font-size:16px; transition:border-color 0.3s; }
        .form-group input:focus, .form-group select:focus { outline:none; border-color:#4facfe; }
        .checkbox-group { display:flex; align-items:center; gap:10px; }
        .checkbox-group input[type="checkbox"] { width:auto; }
        .btn { background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white; border:none; padding:15px 30px; border-radius:8px; font-size:16px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; margin-right:10px; }
        .btn:hover { transform:translateY(-2px); box-shadow:0 10px 20px rgba(0,0,0,0.2); }
        .btn:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
        .btn-secondary { background:linear-gradient(135deg, #6c757d 0%, #495057 100%); }
        .btn-danger { background:linear-gradient(135deg, #dc3545 0%, #b02a37 100%); }
        .progress-section { margin:30px 0; display:none; }
        .progress-bar { width:100%; height:20px; background:#e1e5e9; border-radius:10px; overflow:hidden; margin-bottom:10px; }
        .progress-fill { height:100%; background:linear-gradient(90deg, #4facfe 0%, #00f2fe 100%); width:0%; transition:width 0.3s; }
        .progress-text { text-align:center; font-weight:600; color:#333; }
        .results-section { margin-top:30px; }
        .stats { display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:20px; margin-bottom:30px; }
        .stat-card { background:white; border-radius:10px; padding:20px; text-align:center; box-shadow:0 5px 15px rgba(0,0,0,0.1); border-left:4px solid; }
        .stat-card.total { border-left-color:#6c757d; }
        .stat-card.online { border-left-color:#28a745; }
        .stat-card.offline { border-left-color:#dc3545; }
        .stat-card.errors { border-left-color:#ffc107; }
        .stat-number { font-size:2em; font-weight:bold; margin-bottom:5px; }
        .stat-label { color:#666; font-size:0.9em; }
        .results-table { background:white; border-radius:10px; overflow:hidden; box-shadow:0 5px 15px rgba(0,0,0,0.1); }
        .table-header { background:#f8f9fa; padding:15px 20px; font-weight:600; color:#333; border-bottom:2px solid #e1e5e9; }
        .results-list { max-height:400px; overflow-y:auto; }
        .result-item { padding:15px 20px; border-bottom:1px solid #e1e5e9; display:flex; align-items:center; gap:15px; }
        .result-item:last-child { border-bottom:none; }
        .status-indicator { width:12px; height:12px; border-radius:50%; flex-shrink:0; }
        .status-online { background:#28a745; }
        .status-offline { background:#dc3545; }
        .status-error { background:#ffc107; }
        .result-info { flex:1; }
        .result-ip { font-weight:600; color:#333; font-size:1.1em; }
        .result-hostname { color:#666; font-size:0.9em; margin-top:2px; }
        .result-time { color:#28a745; font-weight:600; font-size:0.9em; }
        .result-actions { display:flex; gap:10px; align-items:center; }
        .btn-vnc { background:linear-gradient(135deg, #17a2b8 0%, #138496 100%); color:white; border:none; padding:8px 16px; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; }
        .btn-vnc:hover { transform:translateY(-1px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }
        .btn-vnc:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
        .btn-shutdown { background:linear-gradient(135deg, #dc3545 0%, #b02a37 100%); color:white; border:none; padding:8px 16px; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; }
        .btn-shutdown:hover { transform:translateY(-1px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }
        .btn-shutdown:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
        .btn-processes { background:linear-gradient(135deg, #28a745 0%, #1e7e34 100%); color:white; border:none; padding:8px 16px; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; }
        .btn-processes:hover { transform:translateY(-1px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }
        .btn-processes:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
        .btn-message { background:linear-gradient(135deg, #17a2b8 0%, #138496 100%); color:white; border:none; padding:8px 16px; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; }
        .btn-message:hover { transform:translateY(-1px); box-shadow:0 5px 15px rgba(0,0,0,0.2); }
        .btn-message:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
        .loading { text-align:center; padding:40px; color:#666; }
        .alert { padding:15px; border-radius:8px; margin-bottom:20px; }
        .alert-error { background:#f8d7da; color:#721c24; border:1px solid #f5c6cb; }
        .alert-success { background:#d4edda; color:#155724; border:1px solid #c3e6cb; }
        .modal { display:none; position:fixed; z-index:1000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.5); }
        .modal-content { background:white; margin:3% auto; padding:0; width:95%; max-width:1400px; border-radius:10px; max-height:85vh; overflow:hidden; }
        .modal-header { background:#f8f9fa; padding:15px 20px; border-bottom:2px solid #e1e5e9; display:flex; justify-content:space-between; align-items:center; }
        .modal-title { font-weight:600; font-size:1.2em; color:#333; }
        .modal-close { background:none; border:none; font-size:24px; cursor:pointer; color:#666; }
        .modal-body { padding:0; max-height:70vh; overflow:auto; }
        .process-controls { padding:15px 20px; background:#f8f9fa; border-bottom:1px solid #e1e5e9; display:flex; gap:15px; align-items:center; flex-wrap:wrap; }
        .process-search { flex:1; min-width:200px; }
        .process-search input { width:100%; padding:8px 12px; border:2px solid #e1e5e9; border-radius:6px; font-size:14px; }
        .process-search input:focus { outline:none; border-color:#4facfe; }
        .process-sort { display:flex; gap:10px; align-items:center; }
        .process-sort select { padding:8px 12px; border:2px solid #e1e5e9; border-radius:6px; font-size:14px; background:white; }
        .process-sort select:focus { outline:none; border-color:#4facfe; }
        .process-table { width:100%; border-collapse:collapse; table-layout:fixed; }
        .process-table th, .process-table td { padding:10px 12px; text-align:left; border-bottom:1px solid #e1e5e9; word-wrap:break-word; }
        .process-table th:nth-child(1), .process-table td:nth-child(1) { width:8%; } /* PID */
        .process-table th:nth-child(2), .process-table td:nth-child(2) { width:20%; } /* Name */
        .process-table th:nth-child(3), .process-table td:nth-child(3) { width:35%; } /* CmdLine/CPU */
        .process-table th:nth-child(4), .process-table td:nth-child(4) { width:12%; } /* User/Mem */
        .process-table th:nth-child(5), .process-table td:nth-child(5) { width:15%; } /* Status */
        .process-table th:nth-child(6), .process-table td:nth-child(6) { width:10%; } /* Actions */
        .process-table th { background:#f8f9fa; font-weight:600; color:#333; cursor:pointer; user-select:none; }
        .process-table th:hover { background:#e9ecef; }
        .process-table th.sortable { position:relative; }
        .process-table th.sortable::after { content:'↕'; position:absolute; right:8px; opacity:0.5; }
        .process-table th.sort-asc::after { content:'↑'; opacity:1; }
        .process-table th.sort-desc::after { content:'↓'; opacity:1; }
        .process-table tr:hover { background:#f8f9fa; }
        .process-pid { font-weight:600; color:#007bff; }
        .process-cpu { color:#28a745; font-weight:600; }
        .process-mem { color:#dc3545; font-weight:600; }
        .btn-kill { background:linear-gradient(135deg, #dc3545 0%, #b02a37 100%); color:white; border:none; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer; transition:transform 0.2s, box-shadow 0.2s; min-width:70px; text-align:center; white-space:nowrap; }
        .btn-kill:hover { transform:translateY(-1px); box-shadow:0 4px 12px rgba(220,53,69,0.3); background:linear-gradient(135deg, #c82333 0%, #a71e2a 100%); }
        .btn-kill:disabled { opacity:0.5; cursor:not-allowed; transform:none; background:#6c757d; box-shadow:none; }
        .btn-kill:disabled:hover { transform:none; box-shadow:none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Scanner</h1>
            <p>Веб-интерфейс для сканирования активных компьютеров в сети</p>
        </div>
        <div class="content">
            <div class="form-section">
                <form id="scanForm">
                    <div class="form-group">
                        <label for="network_range">Диапазон IP адресов:</label>
                        <input type="text" id="network_range" name="network_range" placeholder="192.168.1.1-254">
                        <small style="color:#666;font-size:0.9em;">Форматы: 192.168.1.1-254 или 192.168.1.1-192.168.1.100</small>
                    </div>
                    <div class="form-group">
                        <label for="source_ip">Сетевой интерфейс (исходный IP):</label>
                        <select id="source_ip" name="source_ip"><option value="">Автовыбор системой</option></select>
                        <small style="color:#666;font-size:0.9em;">Можно указать исходный IP для пинга (если поддерживается ОС)</small>
                    </div>
                    <div class="form-group">
                        <label for="timeout">Таймаут пинга (мс):</label>
                        <select id="timeout" name="timeout">
                            <option value="500">500 мс (быстро)</option>
                            <option value="1000" selected>1000 мс (стандартно)</option>
                            <option value="2000">2000 мс (медленно)</option>
                            <option value="5000">5000 мс (очень медленно)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="show_offline" name="show_offline">
                            <label for="show_offline">Показывать отключенные компьютеры</label>
                        </div>
                    </div>
                    <button type="submit" class="btn" id="scanBtn">🚀 Начать сканирование</button>
                    <button type="button" class="btn btn-danger" id="stopBtn" style="display:none;">⛔ Остановить</button>
                    <button type="button" class="btn btn-secondary" id="exportBtn" style="display:none;">📊 Экспорт в CSV</button>
                </form>
            </div>
            <div class="progress-section" id="progressSection">
                <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
                <div class="progress-text" id="progressText">Подготовка к сканированию...</div>
            </div>
            <div class="results-section" id="resultsSection" style="display:none;">
                <div class="stats" id="statsContainer"></div>
                <div class="results-table">
                    <div class="table-header">Результаты сканирования</div>
                    <div class="results-list" id="resultsList"></div>
                </div>
                <div class="form-section" style="margin-top:20px;">
                    <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                        <button type="button" class="btn btn-secondary" id="logRefreshBtn">🔄 Обновить лог</button>
                        <button type="button" class="btn btn-secondary" id="logDownloadBtn">⬇️ Скачать лог</button>
                        <select id="logLines" style="padding:10px; border:2px solid #e1e5e9; border-radius:8px;">
                            <option value="200" selected>Последние 200 строк</option>
                            <option value="500">Последние 500 строк</option>
                            <option value="1000">Последние 1000 строк</option>
                            <option value="2000">Последние 2000 строк</option>
                        </select>
                    </div>
                    <pre id="logViewer" style="margin-top:10px; max-height:250px; overflow:auto; background:#0b1020; color:#b8c1ec; padding:15px; border-radius:8px;"></pre>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modal для отображения процессов -->
    <div id="processModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">🖥️ Процессы компьютера <span id="modalComputerIP"></span></h3>
                <button class="modal-close" onclick="closeProcessModal()">&times;</button>
            </div>
            <div class="modal-body" id="modalProcessesBody">
                <div class="process-controls" id="processControls" style="display:none;">
                    <div class="process-search">
                        <input type="text" id="processSearchInput" placeholder="🔍 Поиск по названию процесса..." onkeyup="try{filterProcesses();}catch(e){console.error('Filter error:',e);}">
                    </div>
                    <div class="process-sort">
                        <label for="processSortSelect">Сортировка:</label>
                        <select id="processSortSelect" onchange="try{sortProcesses();}catch(e){console.error('Sort error:',e);}">
                            <option value="name-asc">По названию (А-Я)</option>
                            <option value="name-desc">По названию (Я-А)</option>
                            <option value="pid-desc">По PID (убывание)</option>
                            <option value="pid-asc">По PID (возрастание)</option>
                            <option value="cpu-desc">По CPU (убывание)</option>
                            <option value="cpu-asc">По CPU (возрастание)</option>
                            <option value="mem-desc">По памяти (убывание)</option>
                            <option value="mem-asc">По памяти (возрастание)</option>
                        </select>
                    </div>
                </div>
                <div class="loading">Загрузка процессов...</div>
            </div>
        </div>
    </div>
    
    <!-- Modal для отправки сообщений -->
    <div id="messageModal" class="modal">
        <div class="modal-content" style="max-width: 600px;">
            <div class="modal-header">
                <h3 class="modal-title">💬 Отправить сообщение на <span id="messageComputerIP"></span></h3>
                <button class="modal-close" onclick="closeMessageModal()">&times;</button>
            </div>
            <div class="modal-body" style="padding: 30px; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 200px;">
                <div class="form-group" style="width: 100%; max-width: 500px;">
                    <label for="messageText" style="text-align: center; display: block; margin-bottom: 15px;">Текст сообщения:</label>
                    <textarea id="messageText" rows="4" style="width: 100%; padding: 12px; border: 2px solid #e1e5e9; border-radius: 8px; text-align: center; font-size: 16px; resize: vertical;" placeholder="Введите сообщение для отправки на компьютер..."></textarea>
                </div>
                <div style="margin-top: 20px; text-align: center;">
                    <button class="btn" onclick="sendMessage()" id="sendMessageBtn">📤 Отправить сообщение</button>
                    <button class="btn btn-secondary" onclick="closeMessageModal()">❌ Отмена</button>
                </div>
                <div id="messageResult" style="margin-top: 15px;"></div>
            </div>
        </div>
    </div>
    
    <script>
        let scanData = null;
        let currentEventSource = null;
        document.getElementById('scanForm').addEventListener('submit', function(e){ e.preventDefault(); startScan(); });
        document.getElementById('exportBtn').addEventListener('click', function(){ if (scanData) exportToCSV(); });
        document.getElementById('logRefreshBtn').addEventListener('click', refreshLog);
        document.getElementById('logDownloadBtn').addEventListener('click', downloadLog);
        document.getElementById('stopBtn').addEventListener('click', stopScan);

        function startScan(){
            const form = document.getElementById('scanForm');
            const scanBtn = document.getElementById('scanBtn');
            const progressSection = document.getElementById('progressSection');
            const resultsSection = document.getElementById('resultsSection');
            const exportBtn = document.getElementById('exportBtn');
            const stopBtn = document.getElementById('stopBtn');
            scanBtn.disabled = true; scanBtn.textContent = '⏳ Сканирование...';
            progressSection.style.display = 'block'; resultsSection.style.display = 'none'; exportBtn.style.display = 'none'; stopBtn.style.display='inline-block'; stopBtn.disabled=false;
            startStreamingScan(form);
        }

        function startStreamingScan(form){
            const scanBtn = document.getElementById('scanBtn');
            const progressSection = document.getElementById('progressSection');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const resultsSection = document.getElementById('resultsSection');
            const resultsList = document.getElementById('resultsList');
            const statsContainer = document.getElementById('statsContainer');
            const exportBtn = document.getElementById('exportBtn');
            const stopBtn = document.getElementById('stopBtn');
            resultsList.innerHTML=''; statsContainer.innerHTML=''; resultsSection.style.display='none';
            progressSection.style.display='block'; progressFill.style.width='0%'; progressText.textContent='Подготовка к сканированию...'; exportBtn.style.display='none';
            scanData = { results: [], stats: { total: 0, online: 0, offline: 0, errors: 0, scan_time: 0 } };
            const params = new URLSearchParams();
            params.set('action','scan_stream'); params.set('network_range', form.network_range.value);
            params.set('timeout', form.timeout.value); params.set('show_offline', form.show_offline.checked ? '1' : '0');
            if (form.source_ip.value) params.set('source_ip', form.source_ip.value);
            if (currentEventSource) { try { currentEventSource.close(); } catch(e){} }
            const es = new EventSource('?' + params.toString());
            currentEventSource = es;
            es.addEventListener('progress', ev => {
                try{
                    const payload = JSON.parse(ev.data);
                    const { progress, index, total, counts, result } = payload;
                    progressFill.style.width = progress + '%';
                    progressText.textContent = 'Прогресс: ' + index + '/' + total + ' (' + progress + '%)';
                    scanData.stats = { total, online: counts.online, offline: counts.offline, errors: counts.errors, scan_time: 0 };
                    renderStats(scanData.stats);
                    if (result) { scanData.results.push(result); appendResultItem(result); throttleRefreshLog(); }
                } catch {}
            });
            es.addEventListener('done', ev => {
                try{
                    const data = JSON.parse(ev.data);
                    scanData = data; progressFill.style.width='100%'; progressText.textContent='Готово';
                    renderStats(scanData.stats); displayResults(scanData); exportBtn.style.display='inline-block'; refreshLog();
                } finally {
                    es.close(); if (currentEventSource===es) currentEventSource=null; scanBtn.disabled=false; scanBtn.textContent='🚀 Начать сканирование'; progressSection.style.display='none'; document.getElementById('stopBtn').style.display='none';
                }
            });
            es.addEventListener('error', ev => {
                es.close(); if (currentEventSource===es) currentEventSource=null; scanBtn.disabled=false; scanBtn.textContent='🚀 Начать сканирование'; progressSection.style.display='none'; document.getElementById('stopBtn').style.display='none';
                showError('Ошибка при сканировании');
            });
        }

        function stopScan(){
            const scanBtn = document.getElementById('scanBtn');
            const stopBtn = document.getElementById('stopBtn');
            stopBtn.disabled = true; stopBtn.textContent = '⏹ Остановка...';
            if (currentEventSource){ try { currentEventSource.close(); } catch(e){} currentEventSource = null; }
            scanBtn.disabled = false; scanBtn.textContent = '🚀 Начать сканирование';
            document.getElementById('progressSection').style.display='none';
            stopBtn.style.display='none';
        }

        function renderStats(stats){
            const el = document.getElementById('statsContainer');
            el.innerHTML =
                '<div class="stat-card total"><div class="stat-number">' + stats.total + '</div><div class="stat-label">Всего проверено</div></div>' +
                '<div class="stat-card online"><div class="stat-number">' + stats.online + '</div><div class="stat-label">Онлайн</div></div>' +
                '<div class="stat-card offline"><div class="stat-number">' + stats.offline + '</div><div class="stat-label">Офлайн</div></div>' +
                '<div class="stat-card errors"><div class="stat-number">' + stats.errors + '</div><div class="stat-label">Ошибки</div></div>';
            document.getElementById('resultsSection').style.display = 'block';
        }
        function appendResultItem(result){
            const list = document.getElementById('resultsList');
            const item = document.createElement('div'); item.className='result-item';
            var hostnameHtml = (result.hostname && result.hostname !== 'Unknown' && result.hostname !== 'N/A') ? ('<div class="result-hostname">' + result.hostname + '</div>') : '';
            var timeHtml = result.response_time ? ('<div class="result-time">' + result.response_time + 'мс</div>') : '<div class="result-time">N/A</div>';
            var vncButton = result.status === 'online' ? 
                '<button class="btn-vnc" onclick="connectVNC(\'' + result.ip + '\')" title="Подключиться через VNC">🖥️ VNC</button>' : 
                '<button class="btn-vnc" disabled title="Компьютер недоступен">🖥️ VNC</button>';
            var processesButton = result.status === 'online' ? 
                '<button class="btn-processes" onclick="showProcesses(\'' + result.ip + '\')" title="Показать процессы">📋 Процессы</button>' : 
                '<button class="btn-processes" disabled title="Компьютер недоступен">📋 Процессы</button>';
            var messageButton = result.status === 'online' ? 
                '<button class="btn-message" onclick="showMessageModal(\'' + result.ip + '\')" title="Отправить сообщение">💬 Сообщение</button>' : 
                '<button class="btn-message" disabled title="Компьютер недоступен">💬 Сообщение</button>';
            var shutdownButton = result.status === 'online' ? 
                '<button class="btn-shutdown" onclick="shutdownComputer(\'' + result.ip + '\')" title="Выключить компьютер">🔌 Выключить</button>' : 
                '<button class="btn-shutdown" disabled title="Компьютер недоступен">🔌 Выключить</button>';
            item.innerHTML =
                '<div class="status-indicator status-' + result.status + '"></div>' +
                '<div class="result-info">' +
                    '<div class="result-ip">' + result.ip + '</div>' +
                    hostnameHtml +
                '</div>' +
                '<div class="result-actions">' +
                    timeHtml +
                    vncButton +
                    processesButton +
                    messageButton +
                    shutdownButton +
                '</div>';
            list.appendChild(item);
        }
        function displayResults(data){
            const list = document.getElementById('resultsList');
            list.innerHTML = '';
            
            // Проверяем, что data и data.results существуют
            if (!data || !data.results || !Array.isArray(data.results) || data.results.length === 0) { 
                list.innerHTML = '<div class="loading">Активные компьютеры не найдены</div>'; 
                return; 
            }
            
            data.results.forEach(r => appendResultItem(r));
        }
        function exportToCSV(){ if (!scanData) return; const body = new FormData(); body.append('action','export'); body.append('data', JSON.stringify(scanData)); fetch('', { method:'POST', body }).then(r=>r.blob()).then(b=>{ const url=URL.createObjectURL(b); const a=document.createElement('a'); a.href=url; a.download='network_scan_'+new Date().toISOString().slice(0,19).replace(/:/g,'-')+'.csv'; document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); document.body.removeChild(a); }).catch(()=>{}); }
        let lastLogRefresh=0; function throttleRefreshLog(){ const now=Date.now(); if (now-lastLogRefresh>1000){ lastLogRefresh=now; refreshLog(); } }
        function refreshLog(){ const lines=document.getElementById('logLines')?.value||'200'; const body=new URLSearchParams({action:'log_tail',lines}); fetch('',{method:'POST', body}).then(r=>r.json()).then(d=>{ const v=document.getElementById('logViewer'); if (v && d && typeof d.text==='string'){ v.textContent=d.text; v.scrollTop=v.scrollHeight; } }).catch(()=>{}); }
        function downloadLog(){ const body=new URLSearchParams({action:'log_download'}); fetch('',{method:'POST', body}).then(r=>r.blob()).then(b=>{ const url=URL.createObjectURL(b); const a=document.createElement('a'); a.href=url; a.download='network_scan.log'; document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); document.body.removeChild(a); }).catch(()=>{}); }
        function connectVNC(ip) {
            // Открываем VNC клиент в новом окне
            const vncUrl = 'vnc_client.html?host=' + encodeURIComponent(ip) + '&port=5900';
            const vncWindow = window.open(vncUrl, 'VNC_' + ip, 'width=1200,height=800,scrollbars=yes,resizable=yes');
            
            if (vncWindow) {
                // Фокусируемся на новом окне
                vncWindow.focus();
            } else {
                alert('Не удалось открыть VNC клиент. Возможно, браузер блокирует всплывающие окна.');
            }
        }
        
        function shutdownComputer(ip) {
            if (!confirm('Вы уверены, что хотите выключить компьютер ' + ip + '?\\n\\nЭто действие нельзя отменить!')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'shutdown');
            formData.append('ip', ip);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Команда выключения отправлена на ' + ip + '\\n\\n' + (data.message || 'Компьютер будет выключен через несколько секунд.'));
                } else {
                    alert('Ошибка при выключении ' + ip + ':\\n' + (data.error || 'Неизвестная ошибка'));
                }
            })
            .catch(error => {
                alert('Ошибка при выключении ' + ip + ':\\n' + error.message);
            });
        }
        
        function showProcesses(ip) {
            const modal = document.getElementById('processModal');
            const modalBody = document.getElementById('modalProcessesBody');
            const modalComputerIP = document.getElementById('modalComputerIP');
            
            // Очищаем предыдущие данные
            currentProcesses = [];
            currentPlatform = '';
            
            modalComputerIP.textContent = ip;
            modal.style.display = 'block';
            
            // Скрываем элементы управления во время загрузки
            const processControls = document.getElementById('processControls');
            if (processControls) {
                processControls.style.display = 'none';
            }
            
            // Очищаем поля поиска и сортировки
            const searchInput = document.getElementById('processSearchInput');
            const sortSelect = document.getElementById('processSortSelect');
            if (searchInput) searchInput.value = '';
            if (sortSelect) sortSelect.value = 'name-asc';
            
            modalBody.innerHTML = '<div class="loading">📋 Загрузка процессов с ' + ip + '...</div>';
            
            const formData = new FormData();
            formData.append('action', 'processes');
            formData.append('ip', ip);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                // Проверяем структуру ответа
                if (!data) {
                    throw new Error('Пустой ответ от сервера');
                }
                
                if (data.success === true && data.processes) {
                    if (Array.isArray(data.processes) && data.processes.length > 0) {
                        modalBody.innerHTML = generateProcessTable(data.processes, data.platform || 'windows');
                    } else {
                        modalBody.innerHTML = '<div class="loading">📋 Процессы не найдены на ' + ip + '</div>';
                    }
                } else {
                    const errorMsg = data.error || data.debug || 'Неизвестная ошибка';
                    modalBody.innerHTML = '<div class="alert alert-error"><strong>Ошибка:</strong> ' + escapeHtml(errorMsg) + '</div>';
                }
            })
            .catch(error => {
                modalBody.innerHTML = '<div class="alert alert-error"><strong>Ошибка:</strong> ' + error.message + '</div>';
            });
        }
        
        let currentProcesses = [];
        let currentPlatform = '';
        
        function generateProcessTable(processes, platform) {
            // Проверяем, что processes существует и является массивом
            if (!processes || !Array.isArray(processes)) {
                return '<div class="alert alert-error"><strong>Ошибка:</strong> Данные процессов не получены</div>';
            }
            
            // Сохраняем данные для фильтрации и сортировки
            currentProcesses = processes;
            currentPlatform = platform;
            
            // Показываем элементы управления
            const processControls = document.getElementById('processControls');
            if (processControls) {
                processControls.style.display = 'flex';
            }
            
            // Сбрасываем сортировку на значение по умолчанию
            const sortSelect = document.getElementById('processSortSelect');
            if (sortSelect) {
                sortSelect.value = 'name-asc';
            }
            
            // Применяем сортировку по умолчанию
            const sortedProcesses = sortProcessesBy(currentProcesses, 'name-asc');
            
            let table = '<table class="process-table" id="processTable">';
            
            if (platform === 'windows') {
                table += '<thead><tr><th class="sortable" onclick="try{sortByColumn(\'pid\');}catch(e){console.error(\'Sort error:\',e);}">PID</th><th class="sortable" onclick="try{sortByColumn(\'name\');}catch(e){console.error(\'Sort error:\',e);}">Имя процесса</th><th>Полный путь</th><th>Пользователь</th><th>Статус</th><th>Действия</th></tr></thead><tbody>';
                
                sortedProcesses.forEach(process => {
                    // Безопасное получение значений с проверкой на undefined
                    const pid = process.PID || 0;
                    const name = process.Name || 'Unknown';
                    const cmdLine = process.CmdLine || '';
                    const user = process.User || 'N/A';
                    const status = process.Status || 'Unknown';
                    
                    // Определяем, можно ли завершить процесс
                    const canKill = pid > 0 && pid !== 0 && pid !== 4 && name !== 'System Idle Process' && name !== 'System';
                    const killButton = canKill ? 
                        '<button class="btn-kill" onclick="killProcess(' + pid + ', \'' + escapeHtml(name) + '\')" title="Завершить процесс">Завершить</button>' :
                        '<button class="btn-kill" disabled title="Нельзя завершить системный процесс">Завершить</button>';
                    
                    table += '<tr>';
                    table += '<td class="process-pid">' + pid + '</td>';
                    table += '<td>' + escapeHtml(name) + '</td>';
                    table += '<td title="' + escapeHtml(cmdLine) + '">' + escapeHtml(cmdLine.length > 50 ? cmdLine.substring(0, 50) + '...' : cmdLine) + '</td>';
                    table += '<td>' + escapeHtml(user) + '</td>';
                    table += '<td>' + escapeHtml(status) + '</td>';
                    table += '<td>' + killButton + '</td>';
                    table += '</tr>';
                });
            } else {
                table += '<thead><tr><th class="sortable" onclick="try{sortByColumn(\'pid\');}catch(e){console.error(\'Sort error:\',e);}">PID</th><th class="sortable" onclick="try{sortByColumn(\'name\');}catch(e){console.error(\'Sort error:\',e);}">Имя процесса</th><th class="sortable" onclick="try{sortByColumn(\'cpu\');}catch(e){console.error(\'Sort error:\',e);}">CPU%</th><th class="sortable" onclick="try{sortByColumn(\'mem\');}catch(e){console.error(\'Sort error:\',e);}">Mem%</th><th>Пользователь</th><th>Статус</th><th>Действия</th></tr></thead><tbody>';
                
                sortedProcesses.forEach(process => {
                    // Безопасное получение значений с проверкой на undefined
                    const pid = process.PID || 0;
                    const name = process.Name || 'Unknown';
                    const cmdLine = process.CmdLine || '';
                    const cpu = process.CPUP || 0;
                    const mem = process.MemP || 0;
                    const user = process.User || 'N/A';
                    const status = process.Status || 'Unknown';
                    
                    // Определяем, можно ли завершить процесс
                    const canKill = pid > 0 && pid !== 0 && pid !== 1 && name !== 'init' && name !== 'systemd';
                    const killButton = canKill ? 
                        '<button class="btn-kill" onclick="killProcess(' + pid + ', \'' + escapeHtml(name) + '\')" title="Завершить процесс">Завершить</button>' :
                        '<button class="btn-kill" disabled title="Нельзя завершить системный процесс">Завершить</button>';
                    
                    table += '<tr>';
                    table += '<td class="process-pid">' + pid + '</td>';
                    table += '<td title="' + escapeHtml(cmdLine) + '">' + escapeHtml(name) + '</td>';
                    table += '<td class="process-cpu">' + cpu.toFixed(1) + '%</td>';
                    table += '<td class="process-mem">' + mem.toFixed(1) + '%</td>';
                    table += '<td>' + escapeHtml(user) + '</td>';
                    table += '<td>' + escapeHtml(status) + '</td>';
                    table += '<td>' + killButton + '</td>';
                    table += '</tr>';
                });
            }
            
            table += '</tbody></table>';
            table += '<div style="padding: 15px; text-align: center; color: #666; font-size: 0.9em;">Найдено процессов: ' + sortedProcesses.length + '</div>';
            table += '<div style="padding: 10px 15px; background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; margin: 10px; font-size: 0.85em; color: #856404;">';
            table += '<strong>⚠️ Важно:</strong> Для завершения процессов на удаленных компьютерах требуются права администратора и настроенное удаленное управление (WMI, PowerShell Remoting, WMIC или SSH).';
            table += '</div>';
            
            return table;
        }
        
        function closeProcessModal() {
            document.getElementById('processModal').style.display = 'none';
            // Скрываем элементы управления при закрытии
            const processControls = document.getElementById('processControls');
            if (processControls) {
                processControls.style.display = 'none';
            }
            // Очищаем поля поиска и сортировки
            const searchInput = document.getElementById('processSearchInput');
            const sortSelect = document.getElementById('processSortSelect');
            if (searchInput) searchInput.value = '';
            if (sortSelect) sortSelect.value = 'name-asc';
            
            // Очищаем данные процессов
            currentProcesses = [];
            currentPlatform = '';
        }
        
        function filterProcesses() {
            const searchInput = document.getElementById('processSearchInput');
            const table = document.getElementById('processTable');
            
            if (!searchInput || !table) return;
            
            const searchTerm = searchInput.value.toLowerCase();
            const rows = table.getElementsByTagName('tr');
            let visibleCount = 0;
            
            for (let i = 1; i < rows.length; i++) { // Пропускаем заголовок
                const cells = rows[i].getElementsByTagName('td');
                if (cells.length > 0) {
                    const processName = cells[1].textContent.toLowerCase(); // Имя процесса во втором столбце
                    const shouldShow = processName.includes(searchTerm);
                    if (rows[i] && rows[i].style) {
                        rows[i].style.display = shouldShow ? '' : 'none';
                    }
                    if (shouldShow) visibleCount++;
                }
            }
            
            // Обновляем счетчик найденных процессов
            const countElement = table.parentNode.querySelector('div[style*="padding: 15px"]');
            if (countElement) {
                countElement.textContent = 'Найдено процессов: ' + visibleCount;
            }
        }
        
        function sortProcesses() {
            const sortSelect = document.getElementById('processSortSelect');
            if (!sortSelect) return;
            
            const sortValue = sortSelect.value;
            
            if (!currentProcesses || currentProcesses.length === 0) return;
            
            const sortedProcesses = sortProcessesBy(currentProcesses, sortValue);
            const modalBody = document.getElementById('modalProcessesBody');
            
            if (!modalBody) return;
            
            // Обновляем таблицу с отсортированными данными
            modalBody.innerHTML = generateProcessTable(sortedProcesses, currentPlatform);
        }
        
        function sortByColumn(column) {
            const sortSelect = document.getElementById('processSortSelect');
            if (!sortSelect) return;
            
            let newSortValue = '';
            
            switch (column) {
                case 'pid':
                    newSortValue = sortSelect.value === 'pid-desc' ? 'pid-asc' : 'pid-desc';
                    break;
                case 'name':
                    newSortValue = sortSelect.value === 'name-desc' ? 'name-asc' : 'name-desc';
                    break;
                case 'cpu':
                    newSortValue = sortSelect.value === 'cpu-desc' ? 'cpu-asc' : 'cpu-desc';
                    break;
                case 'mem':
                    newSortValue = sortSelect.value === 'mem-desc' ? 'mem-asc' : 'mem-desc';
                    break;
            }
            
            if (newSortValue) {
                sortSelect.value = newSortValue;
                sortProcesses();
            }
        }
        
        function sortProcessesBy(processes, sortValue) {
            if (!processes || !Array.isArray(processes)) return [];
            
            const sorted = [...processes]; // Создаем копию массива
            
            switch (sortValue) {
                case 'name-asc':
                    sorted.sort((a, b) => (a.Name || '').localeCompare(b.Name || '', 'ru'));
                    break;
                case 'name-desc':
                    sorted.sort((a, b) => (b.Name || '').localeCompare(a.Name || '', 'ru'));
                    break;
                case 'pid-asc':
                    sorted.sort((a, b) => (a.PID || 0) - (b.PID || 0));
                    break;
                case 'pid-desc':
                    sorted.sort((a, b) => (b.PID || 0) - (a.PID || 0));
                    break;
                case 'cpu-asc':
                    sorted.sort((a, b) => (a.CPUP || 0) - (b.CPUP || 0));
                    break;
                case 'cpu-desc':
                    sorted.sort((a, b) => (b.CPUP || 0) - (a.CPUP || 0));
                    break;
                case 'mem-asc':
                    sorted.sort((a, b) => (a.MemP || 0) - (b.MemP || 0));
                    break;
                case 'mem-desc':
                    sorted.sort((a, b) => (b.MemP || 0) - (a.MemP || 0));
                    break;
                default:
                    // По умолчанию сортируем по имени по возрастанию
                    sorted.sort((a, b) => (a.Name || '').localeCompare(b.Name || '', 'ru'));
            }
            
            return sorted;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }
        
        function killProcess(pid, processName) {
            if (!confirm('Вы уверены, что хотите завершить процесс "' + processName + '" (PID: ' + pid + ')?\\n\\nЭто действие нельзя отменить!')) {
                return;
            }
            
            // Получаем IP адрес компьютера из заголовка модального окна
            const modalComputerIP = document.getElementById('modalComputerIP').textContent;
            
            const formData = new FormData();
            formData.append('action', 'kill_process');
            formData.append('ip', modalComputerIP);
            formData.append('pid', pid);
            formData.append('process_name', processName);
            
            // Показываем индикатор загрузки
            const modalBody = document.getElementById('modalProcessesBody');
            const originalContent = modalBody.innerHTML;
            modalBody.innerHTML = '<div class="loading">⏳ Завершение процесса ' + processName + ' (PID: ' + pid + ')...</div>';
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    alert('Процесс "' + processName + '" (PID: ' + pid + ') успешно завершен!\\n\\n' + (data.message || ''));
                    // Обновляем список процессов
                    showProcesses(modalComputerIP);
                } else {
                    const errorMsg = data.error || 'Неизвестная ошибка';
                    alert('Ошибка при завершении процесса "' + processName + '" (PID: ' + pid + '):\\n\\n' + errorMsg);
                    modalBody.innerHTML = originalContent;
                }
            })
            .catch(error => {
                alert('Ошибка при завершении процесса "' + processName + '":\\n' + error.message);
                modalBody.innerHTML = originalContent;
            });
        }
        
        // Закрытие модального окна при клике вне его
        window.addEventListener('click', function(event) {
            const processModal = document.getElementById('processModal');
            const messageModal = document.getElementById('messageModal');
            if (event.target === processModal) {
                closeProcessModal();
            }
            if (event.target === messageModal) {
                closeMessageModal();
            }
        });
        
        // Функции для работы с модальным окном сообщений
        let currentMessageIP = '';
        
        function showMessageModal(ip) {
            const modal = document.getElementById('messageModal');
            const messageComputerIP = document.getElementById('messageComputerIP');
            const messageText = document.getElementById('messageText');
            const messageResult = document.getElementById('messageResult');
            
            currentMessageIP = ip;
            messageComputerIP.textContent = ip;
            messageText.value = '';
            messageResult.innerHTML = '';
            
            modal.style.display = 'block';
            
            // Фокусируемся на поле ввода
            setTimeout(() => {
                messageText.focus();
            }, 100);
        }
        
        function closeMessageModal() {
            const modal = document.getElementById('messageModal');
            modal.style.display = 'none';
            currentMessageIP = '';
        }
        
        function sendMessage() {
            const messageText = document.getElementById('messageText');
            const sendMessageBtn = document.getElementById('sendMessageBtn');
            const messageResult = document.getElementById('messageResult');
            
            const message = messageText.value.trim();
            
            if (!message) {
                messageResult.innerHTML = '<div class="alert alert-error">Пожалуйста, введите текст сообщения</div>';
                return;
            }
            
            if (!currentMessageIP) {
                messageResult.innerHTML = '<div class="alert alert-error">Ошибка: IP адрес не указан</div>';
                return;
            }
            
            // Показываем индикатор загрузки
            sendMessageBtn.disabled = true;
            sendMessageBtn.textContent = '⏳ Отправка...';
            messageResult.innerHTML = '<div class="loading">Отправка сообщения на ' + currentMessageIP + '...</div>';
            
            const formData = new FormData();
            formData.append('action', 'send_message');
            formData.append('ip', currentMessageIP);
            formData.append('message', message);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    messageResult.innerHTML = '<div class="alert alert-success"><strong>Успешно!</strong> ' + (data.message || 'Сообщение отправлено') + '</div>';
                    messageText.value = '';
                } else {
                    const errorMsg = data.error || 'Неизвестная ошибка';
                    messageResult.innerHTML = '<div class="alert alert-error"><strong>Ошибка:</strong> ' + errorMsg + '</div>';
                }
            })
            .catch(error => {
                messageResult.innerHTML = '<div class="alert alert-error"><strong>Ошибка:</strong> ' + error.message + '</div>';
            })
            .finally(() => {
                sendMessageBtn.disabled = false;
                sendMessageBtn.textContent = '📤 Отправить сообщение';
            });
        }
        
        // Обработка нажатия Enter в поле сообщения
        document.addEventListener('DOMContentLoaded', function() {
            const messageText = document.getElementById('messageText');
            if (messageText) {
                messageText.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && e.ctrlKey) {
                        e.preventDefault();
                        sendMessage();
                    }
                });
            }
        });
        
        // Функции для сохранения и восстановления значений формы
        function saveFormValues() {
            const formData = {
                network_range: document.getElementById('network_range').value,
                source_ip: document.getElementById('source_ip').value,
                timeout: document.getElementById('timeout').value,
                show_offline: document.getElementById('show_offline').checked
            };
            localStorage.setItem('networkScannerForm', JSON.stringify(formData));
        }
        
        function loadFormValues() {
            try {
                const savedData = localStorage.getItem('networkScannerForm');
                if (savedData) {
                    const formData = JSON.parse(savedData);
                    if (formData.network_range) document.getElementById('network_range').value = formData.network_range;
                    if (formData.source_ip) document.getElementById('source_ip').value = formData.source_ip;
                    if (formData.timeout) document.getElementById('timeout').value = formData.timeout;
                    if (formData.show_offline !== undefined) document.getElementById('show_offline').checked = formData.show_offline;
                }
            } catch (e) {
                console.log('Ошибка при загрузке сохраненных значений формы:', e);
            }
        }
        
        // Добавляем обработчики событий для сохранения значений
        document.getElementById('network_range').addEventListener('input', saveFormValues);
        document.getElementById('source_ip').addEventListener('change', saveFormValues);
        document.getElementById('timeout').addEventListener('change', saveFormValues);
        document.getElementById('show_offline').addEventListener('change', saveFormValues);

        document.addEventListener('DOMContentLoaded', ()=>{ 
            fetch('',{method:'POST', body:new URLSearchParams({action:'interfaces'})}).then(r=>r.json()).then(d=>{ 
                const sel=document.getElementById('source_ip'); 
                if (d && Array.isArray(d.interfaces)){ 
                    d.interfaces.forEach(iface=>{ 
                        const opt=document.createElement('option'); 
                        opt.value=iface.ip; 
                        opt.textContent=(iface.name || '') + ' — ' + iface.ip; 
                        sel.appendChild(opt); 
                    }); 
                } 
                // Загружаем сохраненные значения после загрузки интерфейсов
                loadFormValues();
            }).catch(()=>{
                // Загружаем сохраненные значения даже если интерфейсы не загрузились
                loadFormValues();
            }); 
            refreshLog(); 
        });
    </script>
</body>
</html>`
