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
	payload := ScanPayload{Results: results, Stats: stats}
	fmt.Fprintf(w, "event: done\n")
	fmt.Fprintf(w, "data: %s\n\n", toJSON(payload))
	flusher.Flush()
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func main() {
	http.HandleFunc("/", handleIndex)
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	log.Printf("Server started at http://%s (listening on all interfaces)\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

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
        .loading { text-align:center; padding:40px; color:#666; }
        .alert { padding:15px; border-radius:8px; margin-bottom:20px; }
        .alert-error { background:#f8d7da; color:#721c24; border:1px solid #f5c6cb; }
        .alert-success { background:#d4edda; color:#155724; border:1px solid #c3e6cb; }
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
            item.innerHTML =
                '<div class="status-indicator status-' + result.status + '"></div>' +
                '<div class="result-info">' +
                    '<div class="result-ip">' + result.ip + '</div>' +
                    hostnameHtml +
                '</div>' +
                timeHtml;
            list.appendChild(item);
        }
        function displayResults(data){
            const list = document.getElementById('resultsList');
            list.innerHTML = '';
            if (!data.results.length) { list.innerHTML = '<div class="loading">Активные компьютеры не найдены</div>'; return; }
            data.results.forEach(r => appendResultItem(r));
        }
        function exportToCSV(){ if (!scanData) return; const body = new FormData(); body.append('action','export'); body.append('data', JSON.stringify(scanData)); fetch('', { method:'POST', body }).then(r=>r.blob()).then(b=>{ const url=URL.createObjectURL(b); const a=document.createElement('a'); a.href=url; a.download='network_scan_'+new Date().toISOString().slice(0,19).replace(/:/g,'-')+'.csv'; document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); document.body.removeChild(a); }).catch(()=>{}); }
        let lastLogRefresh=0; function throttleRefreshLog(){ const now=Date.now(); if (now-lastLogRefresh>1000){ lastLogRefresh=now; refreshLog(); } }
        function refreshLog(){ const lines=document.getElementById('logLines')?.value||'200'; const body=new URLSearchParams({action:'log_tail',lines}); fetch('',{method:'POST', body}).then(r=>r.json()).then(d=>{ const v=document.getElementById('logViewer'); if (v && d && typeof d.text==='string'){ v.textContent=d.text; v.scrollTop=v.scrollHeight; } }).catch(()=>{}); }
        function downloadLog(){ const body=new URLSearchParams({action:'log_download'}); fetch('',{method:'POST', body}).then(r=>r.blob()).then(b=>{ const url=URL.createObjectURL(b); const a=document.createElement('a'); a.href=url; a.download='network_scan.log'; document.body.appendChild(a); a.click(); URL.revokeObjectURL(url); document.body.removeChild(a); }).catch(()=>{}); }
        document.addEventListener('DOMContentLoaded', ()=>{ fetch('',{method:'POST', body:new URLSearchParams({action:'interfaces'})}).then(r=>r.json()).then(d=>{ const sel=document.getElementById('source_ip'); if (d && Array.isArray(d.interfaces)){ d.interfaces.forEach(iface=>{ const opt=document.createElement('option'); opt.value=iface.ip; opt.textContent=(iface.name || '') + ' — ' + iface.ip; sel.appendChild(opt); }); } }).catch(()=>{}); refreshLog(); });
    </script>
</body>
</html>`
