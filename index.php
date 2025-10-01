<?php
/**
 * Network Scanner - PHP веб-интерфейс для сканирования сети
 * Версия: 1.0
 * Автор: AI Assistant
 * 
 * Требования: PHP 7.0+, веб-сервер с поддержкой exec() или shell_exec()
 */

// Настройки безопасности
ini_set('max_execution_time', 300); // 5 минут максимум
ini_set('memory_limit', '256M');

// Лог сканирования
if (!defined('SCAN_LOG_FILE')) {
    define('SCAN_LOG_FILE', __DIR__ . DIRECTORY_SEPARATOR . 'network_scan.log');
}

if (!function_exists('logEvent')) {
function logEvent($type, $payload = []) {
    $record = date('c') . "\t" . $type . "\t" . json_encode($payload, JSON_UNESCAPED_UNICODE) . PHP_EOL;
    @file_put_contents(SCAN_LOG_FILE, $record, FILE_APPEND | LOCK_EX);
}
}

if (!function_exists('tailFile')) {
function tailFile($file, $lines = 200) {
    if (!is_file($file)) return '';
    $f = @fopen($file, 'rb');
    if ($f === false) return '';
    $buffer = '';
    $chunkSize = 4096;
    $pos = -1;
    $newlines = 0;
    $stat = fstat($f);
    $size = $stat['size'];
    while (-$pos < $size) {
        $seek = max(-$size, $pos - $chunkSize);
        fseek($f, $seek, SEEK_END);
        $read = fread($f, -$seek - $pos);
        $buffer = $read . $buffer;
        $pos = $seek;
        $newlines = substr_count($buffer, "\n");
        if ($newlines > $lines) break;
    }
    fclose($f);
    $parts = explode("\n", $buffer);
    if (count($parts) > $lines) {
        $parts = array_slice($parts, -$lines);
    }
    return implode("\n", $parts);
}
}

// Функция для получения IP адреса клиента
if (!function_exists('getClientIP')) {
function getClientIP() {
    $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}
}

// Функция для получения локальной сети
if (!function_exists('getLocalNetwork')) {
function getLocalNetwork() {
    $ip = getClientIP();
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return '192.168.1.1-254'; // Fallback для внешних IP
    }
    
    $parts = explode('.', $ip);
    if (count($parts) == 4) {
        return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.1-254';
    }
    
    return '192.168.1.1-254';
}
}

// Функция для получения списка сетевых интерфейсов (имя и IPv4)
if (!function_exists('getNetworkInterfaces')) {
function getNetworkInterfaces() {
	$interfaces = [];
	$isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

	if ($isWindows) {
		$output = [];
		exec('ipconfig', $output);
		$currentName = null;
		foreach ($output as $line) {
			$line = trim($line);
			if ($line === '') { continue; }
			// Заголовок адаптера
			if (preg_match('/^(Адаптер|Ethernet adapter|Wireless LAN adapter|Адаптер беспроводной сети)\s+(.+):$/ui', $line, $m)) {
				$currentName = trim($m[2]);
				continue;
			}
			// IPv4-адрес (рус) или IPv4 Address (eng)
			if (preg_match('/IPv4[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})/ui', $line, $m)) {
				$ip = $m[1];
				if ($ip !== '127.0.0.1') {
					$interfaces[] = [
						'name' => $currentName ?: 'Interface',
						'ip' => $ip
					];
				}
			}
		}
	} else {
		$output = [];
		exec('ip -4 -o addr', $output);
		foreach ($output as $line) {
			// Формат: 2: eth0    inet 192.168.1.10/24 ...
			if (preg_match('/\d+:\s+(\S+)\s+inet\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\//', $line, $m)) {
				$ifName = $m[1];
				$ip = $m[2];
				if ($ip !== '127.0.0.1') {
					$interfaces[] = [
						'name' => $ifName,
						'ip' => $ip
					];
				}
			}
		}
	}

	return $interfaces;
}
}

// Функция для сканирования сети
if (!function_exists('scanNetwork')) {
function scanNetwork($networkRange, $timeout = 1000, $sourceIp = null) {
    $results = [];
    $onlineCount = 0;
    $offlineCount = 0;
    $errorCount = 0;
    
    // Парсим диапазон IP
    $ipList = parseIPRange($networkRange);
    
    if (empty($ipList)) {
        return ['error' => 'Неверный формат диапазона IP адресов'];
    }
    
    $total = count($ipList);
    $startTime = microtime(true);
    logEvent('START', ['range' => $networkRange, 'timeout' => $timeout, 'source_ip' => $sourceIp]);
    
	foreach ($ipList as $index => $ip) {
		$result = pingHost($ip, $timeout, $sourceIp);
        $result['index'] = $index + 1;
        $result['total'] = $total;
        $result['progress'] = round((($index + 1) / $total) * 100, 2);
        
        if ($result['status'] === 'online') {
            $onlineCount++;
            $result['hostname'] = getHostnameByIP($ip);
        } else {
            $result['hostname'] = 'N/A';
            if ($result['status'] === 'offline') {
                $offlineCount++;
            } else {
                $errorCount++;
            }
        }
        
        $results[] = $result;
        logEvent('ENTRY', $result);
    }
    
    $endTime = microtime(true);
    $scanTime = round($endTime - $startTime, 2);
    
    $summary = [
        'results' => $results,
        'stats' => [
            'total' => $total,
            'online' => $onlineCount,
            'offline' => $offlineCount,
            'errors' => $errorCount,
            'scan_time' => $scanTime
        ]
    ];
    logEvent('DONE', $summary['stats']);
    return $summary;
}
}

// Функция для парсинга диапазона IP
if (!function_exists('parseIPRange')) {
function parseIPRange($range) {
    $ips = [];
    
    if (preg_match('/^(\d+\.\d+\.\d+\.\d+)-(\d+)$/', $range, $matches)) {
        $baseIP = $matches[1];
        $endRange = (int)$matches[2];
        $ipParts = explode('.', $baseIP);
        $baseOctet = (int)$ipParts[3];
        
        for ($i = $baseOctet; $i <= $endRange; $i++) {
            $ips[] = $ipParts[0] . '.' . $ipParts[1] . '.' . $ipParts[2] . '.' . $i;
        }
    } elseif (preg_match('/^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$/', $range, $matches)) {
        $startIP = $matches[1];
        $endIP = $matches[2];
        
        $startParts = explode('.', $startIP);
        $endParts = explode('.', $endIP);
        
        for ($i = (int)$startParts[0]; $i <= (int)$endParts[0]; $i++) {
            for ($j = (int)$startParts[1]; $j <= (int)$endParts[1]; $j++) {
                for ($k = (int)$startParts[2]; $k <= (int)$endParts[2]; $k++) {
                    for ($l = (int)$startParts[3]; $l <= (int)$endParts[3]; $l++) {
                        $ips[] = "$i.$j.$k.$l";
                    }
                }
            }
        }
    }
    
    return $ips;
}
}

// Функция для пинга хоста
if (!function_exists('pingHost')) {
function pingHost($ip, $timeout, $sourceIp = null) {
    $startTime = microtime(true);
    
    // Определяем ОС и команду пинга
    $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    
	if ($isWindows) {
		$sourceArg = '';
		if ($sourceIp && filter_var($sourceIp, FILTER_VALIDATE_IP)) {
			$sourceArg = ' -S ' . escapeshellarg($sourceIp);
		}
		$command = "ping -n 1 -w " . (int)$timeout . $sourceArg . " " . escapeshellarg($ip) . " 2>nul";
	} else {
		$timeoutSec = max(1, (int)ceil($timeout / 1000));
		$sourceArg = '';
		if ($sourceIp && filter_var($sourceIp, FILTER_VALIDATE_IP)) {
			$sourceArg = ' -I ' . escapeshellarg($sourceIp);
		}
		$command = "ping -c 1 -W " . $timeoutSec . $sourceArg . " " . escapeshellarg($ip) . " 2>/dev/null";
	}
    
    $output = [];
    $returnCode = 0;
    exec($command, $output, $returnCode);
    
    $endTime = microtime(true);
    $responseTime = round(($endTime - $startTime) * 1000, 2);
    
    if ($returnCode === 0) {
        return [
            'ip' => $ip,
            'status' => 'online',
            'response_time' => $responseTime,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    } else {
        return [
            'ip' => $ip,
            'status' => 'offline',
            'response_time' => null,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
}

// Функция для получения имени хоста
if (!function_exists('getHostnameByIP')) {
    function getHostnameByIP($ip) {
        $hostname = @gethostbyaddr($ip);
        return ($hostname && $hostname !== $ip) ? $hostname : 'Unknown';
    }
}

// Функция для выключения компьютера
if (!function_exists('shutdownComputer')) {
    function shutdownComputer($ip) {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        
        if ($isWindows) {
            // Windows: используем PowerShell Stop-Computer
            $command = "powershell -Command \"Stop-Computer -ComputerName " . escapeshellarg($ip) . " -Force -Confirm:\$false\" 2>nul";
        } else {
            // Linux/Unix: используем ssh с sudo shutdown
            $command = "ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@" . escapeshellarg($ip) . " 'sudo shutdown -h +1 \"Выключение по команде Network Scanner\"' 2>/dev/null";
        }
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        if ($returnCode === 0) {
            return [
                'success' => true,
                'message' => 'Команда выключения отправлена успешно'
            ];
        } else {
            // Попробуем альтернативные методы
            if ($isWindows) {
                // Попробуем через shutdown.exe как резервный метод
                $shutdownCommand = "shutdown /s /m \\\\" . escapeshellarg($ip) . " /t 10 /c \"Выключение по команде Network Scanner\" 2>nul";
                exec($shutdownCommand, $shutdownOutput, $shutdownReturnCode);
                
                if ($shutdownReturnCode === 0) {
                    return [
                        'success' => true,
                        'message' => 'Команда выключения отправлена через shutdown.exe'
                    ];
                }
            } else {
                // Попробуем через rsh или telnet
                $rshCommand = "rsh " . escapeshellarg($ip) . " 'sudo shutdown -h +1' 2>/dev/null";
                exec($rshCommand, $rshOutput, $rshReturnCode);
                
                if ($rshReturnCode === 0) {
                    return [
                        'success' => true,
                        'message' => 'Команда выключения отправлена через RSH'
                    ];
                }
            }
            
            return [
                'success' => false,
                'error' => 'Не удалось отправить команду выключения. Возможно, требуется настройка удаленного управления или отсутствуют права доступа.'
            ];
        }
    }
}

// Функция для запуска VNC клиента
if (!function_exists('startVNCClient')) {
    function startVNCClient($ip) {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $vncClient = '';
        $args = [$ip];
        
        if ($isWindows) {
            // Попробуем найти VNC клиент в Windows
            $possibleClients = [
                'vncviewer.exe',
                'tightvnc.exe', 
                'ultravnc.exe',
                'realvnc.exe',
            ];
            
            foreach ($possibleClients as $client) {
                $output = [];
                exec("where $client 2>nul", $output);
                if (!empty($output)) {
                    $vncClient = $client;
                    break;
                }
            }
            
            // Если не найден в PATH, попробуем стандартные пути
            if (empty($vncClient)) {
                $standardPaths = [
                    'C:\\Program Files\\TightVNC\\vncviewer.exe',
                    'C:\\Program Files (x86)\\TightVNC\\vncviewer.exe',
                    'C:\\Program Files\\UltraVNC\\vncviewer.exe',
                    'C:\\Program Files (x86)\\UltraVNC\\vncviewer.exe',
                    'C:\\Program Files\\RealVNC\\VNC Viewer\\vncviewer.exe',
                    'C:\\Program Files (x86)\\RealVNC\\VNC Viewer\\vncviewer.exe',
                ];
                
                foreach ($standardPaths as $path) {
                    if (file_exists($path)) {
                        $vncClient = $path;
                        break;
                    }
                }
            }
        } else {
            // Linux/macOS/BSD
            $possibleClients = [
                'vncviewer',
                'xtightvncviewer', 
                'x11vnc',
                'tigervnc',
            ];
            
            foreach ($possibleClients as $client) {
                $output = [];
                exec("which $client 2>/dev/null", $output);
                if (!empty($output)) {
                    $vncClient = $client;
                    break;
                }
            }
        }
        
        if (empty($vncClient)) {
            return [
                'success' => false,
                'error' => 'VNC клиент не найден. Установите TightVNC, UltraVNC, RealVNC или другой VNC клиент'
            ];
        }
        
        // Запускаем VNC клиент
        $command = escapeshellarg($vncClient) . ' ' . escapeshellarg($ip);
        if ($isWindows) {
            $command = "start /B $command";
        } else {
            $command .= ' &';
        }
        
        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);
        
        if ($returnCode !== 0) {
            return [
                'success' => false,
                'error' => 'Не удалось запустить VNC клиент: ' . implode(' ', $output)
            ];
        }
        
        return ['success' => true];
    }
}

// Обработка AJAX запросов
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
	
    switch ($_POST['action']) {
        case 'log_tail':
            $lines = isset($_POST['lines']) ? max(10, min(2000, (int)$_POST['lines'])) : 200;
            $data = tailFile(SCAN_LOG_FILE, $lines);
            echo json_encode(['text' => $data]);
            exit;
        case 'log_download':
            if (!file_exists(SCAN_LOG_FILE)) { echo json_encode(['error' => 'Лог отсутствует']); exit; }
            header('Content-Type: text/plain');
            header('Content-Disposition: attachment; filename="network_scan.log"');
            readfile(SCAN_LOG_FILE);
            exit;
		case 'interfaces':
			$ifs = getNetworkInterfaces();
			echo json_encode(['interfaces' => $ifs]);
			exit;
        case 'scan':
            $networkRange = $_POST['network_range'] ?? getLocalNetwork();
            $timeout = (int)($_POST['timeout'] ?? 1000);
            $showOffline = isset($_POST['show_offline']);
			$sourceIp = $_POST['source_ip'] ?? null;
            
			$result = scanNetwork($networkRange, $timeout, $sourceIp);
            
            if (!$showOffline && isset($result['results'])) {
                $result['results'] = array_filter($result['results'], function($item) {
                    return $item['status'] === 'online';
                });
            }
            
			echo json_encode($result);
            exit;
            
        case 'export':
            $data = json_decode($_POST['data'], true);
            $filename = 'network_scan_' . date('Y-m-d_H-i-s') . '.csv';
            
            header('Content-Type: text/csv');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            
            $output = fopen('php://output', 'w');
            fputcsv($output, ['IP Address', 'Status', 'Response Time (ms)', 'Hostname', 'Timestamp']);
            
            foreach ($data['results'] as $result) {
                fputcsv($output, [
                    $result['ip'],
                    $result['status'],
                    $result['response_time'] ?? 'N/A',
                    $result['hostname'] ?? 'N/A',
                    $result['timestamp']
                ]);
            }
            
            fclose($output);
            exit;
            
        case 'vnc_connect':
            $ip = $_POST['ip'] ?? '';
            if (empty($ip)) {
                echo json_encode(['success' => false, 'error' => 'IP адрес не указан']);
                exit;
            }
            
            $result = startVNCClient($ip);
            if ($result['success']) {
                logEvent('VNC_START', ['ip' => $ip]);
                echo json_encode(['success' => true]);
            } else {
                logEvent('VNC_ERROR', ['ip' => $ip, 'error' => $result['error']]);
                echo json_encode(['success' => false, 'error' => $result['error']]);
            }
            exit;
            
        case 'shutdown':
            $ip = $_POST['ip'] ?? '';
            if (empty($ip)) {
                echo json_encode(['success' => false, 'error' => 'IP адрес не указан']);
                exit;
            }
            
            $result = shutdownComputer($ip);
            if ($result['success']) {
                logEvent('SHUTDOWN_SUCCESS', ['ip' => $ip, 'message' => $result['message']]);
                echo json_encode(['success' => true, 'message' => $result['message']]);
            } else {
                logEvent('SHUTDOWN_ERROR', ['ip' => $ip, 'error' => $result['error']]);
                echo json_encode(['success' => false, 'error' => $result['error']]);
            }
            exit;
    }
}

// Потоковая передача результатов сканирования (SSE)
if (isset($_GET['action']) && $_GET['action'] === 'scan_stream') {
	// Подготовка SSE
	header('Content-Type: text/event-stream');
	header('Cache-Control: no-cache');
	header('Connection: keep-alive');
	// Отключаем буферизацию
	@ini_set('output_buffering', 'off');
	@ini_set('zlib.output_compression', 0);
	while (ob_get_level() > 0) { ob_end_flush(); }
	ob_implicit_flush(true);

	$networkRange = $_GET['network_range'] ?? getLocalNetwork();
	$timeout = (int)($_GET['timeout'] ?? 1000);
	$showOffline = isset($_GET['show_offline']) && $_GET['show_offline'] === '1';
	$sourceIp = $_GET['source_ip'] ?? null;

    logEvent('START', ['range' => $networkRange, 'timeout' => $timeout, 'source_ip' => $sourceIp, 'stream' => true]);
    $ipList = parseIPRange($networkRange);
	if (empty($ipList)) {
		echo "event: error\n";
		echo 'data: ' . json_encode(['error' => 'Неверный формат диапазона IP адресов']) . "\n\n";
		flush();
		exit;
	}

	$total = count($ipList);
	$onlineCount = 0; $offlineCount = 0; $errorCount = 0;
	$results = [];
	$startTime = microtime(true);

	foreach ($ipList as $index => $ip) {
		$result = pingHost($ip, $timeout, $sourceIp);
		$result['index'] = $index + 1;
		$result['total'] = $total;
		$result['progress'] = round((($index + 1) / $total) * 100, 2);
		$result['hostname'] = ($result['status'] === 'online') ? getHostnameByIP($ip) : 'N/A';
		if ($result['status'] === 'online') { $onlineCount++; }
		elseif ($result['status'] === 'offline') { $offlineCount++; } else { $errorCount++; }

        $results[] = $result;
        logEvent('ENTRY', $result);
		if (!$showOffline && $result['status'] !== 'online') {
			// Все равно отправляем прогресс, но без добавления офлайн в список клиента
			echo "event: progress\n";
			echo 'data: ' . json_encode([
				'progress' => $result['progress'],
				'index' => $result['index'],
				'total' => $total,
				'counts' => ['online' => $onlineCount, 'offline' => $offlineCount, 'errors' => $errorCount],
				'result' => null
			]) . "\n\n";
			flush();
			continue;
		}

		echo "event: progress\n";
		echo 'data: ' . json_encode([
			'progress' => $result['progress'],
			'index' => $result['index'],
			'total' => $total,
			'counts' => ['online' => $onlineCount, 'offline' => $offlineCount, 'errors' => $errorCount],
			'result' => $result
		]) . "\n\n";
		flush();
	}

	$endTime = microtime(true);
	$scanTime = round($endTime - $startTime, 2);

	$payload = [
		'results' => $results,
		'stats' => [
			'total' => $total,
			'online' => $onlineCount,
			'offline' => $offlineCount,
			'errors' => $errorCount,
			'scan_time' => $scanTime
		]
	];

    logEvent('DONE', $payload['stats']);
	echo "event: done\n";
	echo 'data: ' . json_encode($payload) . "\n\n";
	flush();
	exit;
}

// WebSocket прокси для VNC (простая реализация)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'websockify') {
    // Простая заглушка - в реальном проекте нужен WebSocket сервер
    header('Content-Type: application/json');
    echo json_encode(['error' => 'WebSocket прокси не реализован в PHP версии. Используйте Go версию для VNC подключения.']);
    exit;
}

// Роут noVNC: отдаём HTML страницу noVNC, как в Go версии
// Сработает при обращении по пути, оканчивающемуся на "/novnc"
$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '/';
// Отдаём локальный noVNC бандл по запросу ?static=novnc.js (не зависит от серверных роутов)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['static']) && $_GET['static'] === 'novnc.js') {
	$cachePath = __DIR__ . DIRECTORY_SEPARATOR . 'novnc.cache.js';
	$srcUrls = [
		// Локальный файл (если есть)
		'?static=novnc.js',
		// Альтернативные CDN
		'https://unpkg.com/novnc@1.2.0/lib/rfb.js',
		'https://cdnjs.cloudflare.com/ajax/libs/novnc/1.2.0/rfb.js',
		'https://cdn.skypack.dev/@novnc/novnc@1.2.0/lib/rfb.js',
		// jsDelivr (может не работать из-за CommonJS)
		'https://cdn.jsdelivr.net/npm/novnc@1.2.0/lib/rfb.js',
		// Резервные источники
		'https://raw.githubusercontent.com/novnc/noVNC/v1.2.0/lib/rfb.js',
		'https://raw.githubusercontent.com/novnc/noVNC/v1.1.0/lib/rfb.js'
	];
	$needFetch = true;
	if (is_file($cachePath)) {
		$mtime = @filemtime($cachePath) ?: 0;
		if (time() - $mtime < 86400) { // 1 день
			$needFetch = false;
		}
	}
	if ($needFetch) {
		foreach ($srcUrls as $u) {
			$data = '';
			// Попытка через cURL
			if (function_exists('curl_init')) {
				$ch = curl_init($u);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
				curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
				curl_setopt($ch, CURLOPT_TIMEOUT, 10);
				curl_setopt($ch, CURLOPT_USERAGENT, 'Network-Scanner/1.0');
				$data = curl_exec($ch);
				$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
				curl_close($ch);
				if ($code >= 200 && $code < 300 && $data && strlen($data) > 1000) {
					@file_put_contents($cachePath, $data, LOCK_EX);
					break;
				}
			}
			// Попытка через file_get_contents
			$ctx = stream_context_create(['http' => ['timeout' => 6], 'https' => ['timeout' => 6]]);
			$data = @file_get_contents($u, false, $ctx);
			if ($data && strlen($data) > 1000) {
				@file_put_contents($cachePath, $data, LOCK_EX);
				break;
			}
		}
	}
	if (!is_file($cachePath)) {
		header('Content-Type: application/javascript');
		echo '/* noVNC не удалось скачать автоматически. */\n';
		echo '/* Скачайте rfb.js (noVNC v1.2.0) и сохраните рядом с index.php как novnc.cache.js */\n';
		echo '/* Например: https://unpkg.com/novnc@1.2.0/lib/rfb.js */\n';
		echo '/* Заглушка для window.RFB */\n';
		echo 'window.RFB = window.RFB || function() { throw new Error("noVNC RFB не загружен. Проверьте подключение к интернету."); };';
		exit;
	}
	// Отдаём файл и кэшируем браузером
	header('Content-Type: application/javascript');
	header('Cache-Control: public, max-age=86400');
	readfile($cachePath);
	exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'GET' && preg_match('#/novnc/?$#', $requestPath)) {
	// Тот же HTML, что и в Go: noVNC одностраничный клиент
	$novncHtml = <<<'HTML'
<!DOCTYPE html>
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
        <div class="form-group">
            <label for="vncQuality">Качество изображения:</label>
            <select id="vncQuality">
                <option value="0">Низкое (быстро)</option>
                <option value="3">Среднее</option>
                <option value="6" selected>Хорошее</option>
                <option value="9">Высокое (медленно)</option>
            </select>
        </div>
        <div class="form-group">
            <label for="vncCompression">Сжатие:</label>
            <select id="vncCompression">
                <option value="0">Без сжатия</option>
                <option value="1">Низкое</option>
                <option value="2" selected>Среднее</option>
                <option value="9">Высокое</option>
            </select>
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

    <!-- WebRTC адаптер для лучшей совместимости -->
    <script src="https://cdn.jsdelivr.net/npm/webrtc-adapter@8.2.3/adapter.min.js" onerror="console.warn('WebRTC adapter failed to load')"></script>
    
    <!-- Загрузчик novnc.min.js: сперва пробуем указанный CDN, затем локальный ?static=novnc.js -->
    <script>
        (function(){
            // Заглушка для CommonJS exports
            if (typeof exports === 'undefined') {
                window.exports = {};
            }
            if (typeof module === 'undefined') {
                window.module = { exports: {} };
            }
            if (typeof require === 'undefined') {
                window.require = function(id) {
                    console.warn('require called for:', id, '- noVNC may not work properly');
                    // Возвращаем пустой объект вместо ошибки
                    return {};
                };
            }
            
            function load(src){
                return new Promise((resolve, reject)=>{
                    var s=document.createElement('script');
                    s.src=src; s.async=true; s.onload=()=>resolve(true); s.onerror=()=>reject(new Error('load failed'));
                    document.head.appendChild(s);
                });
            }
            async function ensureRFB(){
                if (window.RFB) return true;
                
                // Список CDN для попытки загрузки (приоритет: локальный файл)
                const cdnUrls = [
                    // Локальный файл (если есть)
                    '?static=novnc.js',
                    // Альтернативные CDN
                    'https://unpkg.com/novnc@1.2.0/lib/rfb.js',
                    'https://cdnjs.cloudflare.com/ajax/libs/novnc/1.2.0/rfb.js',
                    'https://cdn.skypack.dev/@novnc/novnc@1.2.0/lib/rfb.js',
                    // jsDelivr (может не работать из-за CommonJS)
                    'https://cdn.jsdelivr.net/npm/novnc@1.2.0/lib/rfb.js',
                    // Резервные источники
                    'https://raw.githubusercontent.com/novnc/noVNC/v1.2.0/lib/rfb.js',
                    'https://raw.githubusercontent.com/novnc/noVNC/v1.1.0/lib/rfb.js'
                ];
                
                // Пробуем загрузить с CDN
                for (const url of cdnUrls) {
                    try {
                        console.log('Trying to load noVNC from:', url);
                        await load(url);
                        
                        // Проверяем разные способы экспорта
                        if (window.RFB) {
                            console.log('RFB loaded successfully from:', url);
                            return true;
                        }
                        
                        // Для ES модулей (Skypack)
                        if (window.RFB) {
                            console.log('RFB loaded as ES module from:', url);
                            return true;
                        }
                        
                        // Для CommonJS модулей
                        if (window.module && window.module.exports && window.module.exports.default) {
                            window.RFB = window.module.exports.default;
                            console.log('RFB loaded as CommonJS from:', url);
                            return true;
                        }
                        if (window.exports && window.exports.default) {
                            window.RFB = window.exports.default;
                            console.log('RFB loaded as exports from:', url);
                            return true;
                        }
                        
                        // Для старых версий noVNC
                        if (window.RFB) {
                            console.log('RFB loaded as legacy from:', url);
                            return true;
                        }
                        
                        console.log('RFB not found after loading from:', url);
                    } catch(e) {
                        console.warn('Failed to load from', url, e);
                    }
                }
                
                // Пробуем локальный файл
                try {
                    await load('?static=novnc.js');
                    if (window.RFB) return true;
                    if (window.module && window.module.exports && window.module.exports.default) {
                        window.RFB = window.module.exports.default;
                        return true;
                    }
                    if (window.exports && window.exports.default) {
                        window.RFB = window.exports.default;
                        return true;
                    }
                } catch(e) {
                    console.warn('Failed to load local noVNC', e);
                }
                
                // Если ничего не сработало, создаем заглушку
                console.error('noVNC не удалось загрузить ни с одного источника');
                window.RFB = function() {
                    throw new Error('noVNC RFB не загружен. Проверьте подключение к интернету или скачайте rfb.js вручную с https://unpkg.com/novnc@1.2.0/lib/rfb.js');
                };
                return false;
            }
            window.__rfbReady = ensureRFB();
        })();
    </script>
    
    <script>
        let rfb = null;
        let isConnected = false;
        
        // Получаем параметры из URL
        const urlParams = new URLSearchParams(window.location.search);
        const host = urlParams.get('host');
        const port = urlParams.get('port') || '5900';
        const password = urlParams.get('password') || '';
        const quality = urlParams.get('quality') || '6';
        const compression = urlParams.get('compression') || '2';
        
        // Заполняем форму, если параметры переданы
        if (host) {
            document.getElementById('vncHost').value = host;
            document.getElementById('vncPort').value = port;
            document.getElementById('vncPassword').value = password;
            document.getElementById('vncQuality').value = quality;
            document.getElementById('vncCompression').value = compression;
        }
        
        function connectVNC() {
            const host = document.getElementById('vncHost').value.trim();
            const port = document.getElementById('vncPort').value.trim();
            const password = document.getElementById('vncPassword').value;
            const quality = parseInt(document.getElementById('vncQuality').value);
            const compression = parseInt(document.getElementById('vncCompression').value);
            
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
            
            (async () => {
            try {
                // Ждём загрузки RFB
                try { 
                    const rfbReady = await (window.__rfbReady || Promise.resolve(!!window.RFB));
                    if (!rfbReady) {
                        throw new Error('noVNC RFB не загружен');
                    }
                } catch(e){
                    console.error('RFB loading failed:', e);
                    throw new Error('noVNC RFB не загружен: ' + e.message);
                }
                
                if (!window.RFB){
                    throw new Error('noVNC RFB не загружен');
                }
                
                // Создаём RFB с улучшенными опциями
                rfb = new window.RFB(canvas, url, { 
                    credentials: { password: password },
                    shared: true,
                    repeaterID: '',
                    wsProtocols: ['binary']
                });
                
                // Настройка качества и масштабирования
                rfb.scaleViewport = true;
                rfb.resizeSession = false;
                rfb.qualityLevel = quality; // 0-9, где 9 - лучшее качество
                rfb.compressionLevel = compression; // 0-9, где 0 - без сжатия
                
                // Обработчики событий
                rfb.addEventListener('connect', onConnect);
                rfb.addEventListener('disconnect', onDisconnect);
                rfb.addEventListener('credentialsrequired', onCredentialsRequired);
                rfb.addEventListener('securityfailure', onSecurityFailure);
                rfb.addEventListener('clipboard', onClipboard);
                rfb.addEventListener('bell', onBell);
                rfb.addEventListener('servercuttext', onServerCutText);
                
            } catch (error) {
                console.error('VNC connection error:', error);
                showError('Ошибка подключения: ' + error.message);
                setStatus('disconnected', 'Ошибка подключения');
                document.getElementById('connectBtn').disabled = false;
                document.getElementById('disconnectBtn').disabled = true;
            }
            })();
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
            canvas.innerHTML = `
                <div class="loading">
                    <div>🖥️ Готов к подключению</div>
                    <div style="font-size: 14px; margin-top: 10px; opacity: 0.7;">
                        Введите данные VNC сервера и нажмите "Подключиться"
                    </div>
                </div>
            `;
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
            console.log('Clipboard data:', e.detail.text);
        }
        
        function onBell() {
            // Обработка звукового сигнала от VNC сервера
            console.log('VNC server bell');
            // Можно добавить уведомление или звук
        }
        
        function onServerCutText(e) {
            // Обработка текста, скопированного на сервере
            console.log('Server cut text:', e.detail.text);
        }
        
        function setStatus(type, message) {
            const statusBar = document.getElementById('statusBar');
            statusBar.className = 'status ' + type;
            statusBar.textContent = 'Статус: ' + message;
        }
        
        function showError(message) {
            const canvas = document.getElementById('vncCanvas');
            canvas.innerHTML = `
                <div class="error">
                    <strong>Ошибка:</strong> ${message}
                </div>
            `;
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
            }, 1000); // Увеличиваем задержку для загрузки библиотеки
        }
        
        // Показываем статус загрузки
        document.addEventListener('DOMContentLoaded', () => {
            const statusBar = document.getElementById('statusBar');
            if (statusBar) {
                statusBar.textContent = 'Статус: Загрузка noVNC библиотеки...';
            }
            
            // Проверяем загрузку через 2 секунды
            setTimeout(() => {
                if (window.RFB) {
                    if (statusBar) {
                        statusBar.textContent = 'Статус: noVNC загружен, готов к подключению';
                        statusBar.className = 'status';
                    }
                } else {
                    if (statusBar) {
                        statusBar.textContent = 'Статус: Ошибка загрузки noVNC';
                        statusBar.className = 'status disconnected';
                    }
                }
            }, 2000);
        });
    </script>
</body>
</html>
HTML;
	header('Content-Type: text/html; charset=utf-8');
	echo $novncHtml;
	exit;
}
?>

<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner - Веб-интерфейс</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .form-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input, .form-group select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #4facfe;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-right: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
        }
        .btn-danger {
            background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%);
        }
        
        .progress-section {
            margin: 30px 0;
            display: none;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e1e5e9;
            border-radius: 10px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
            width: 0%;
            transition: width 0.3s;
        }
        
        .progress-text {
            text-align: center;
            font-weight: 600;
            color: #333;
        }
        
        .results-section {
            margin-top: 30px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        
        .stat-card.total { border-left-color: #6c757d; }
        .stat-card.online { border-left-color: #28a745; }
        .stat-card.offline { border-left-color: #dc3545; }
        .stat-card.errors { border-left-color: #ffc107; }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        
        .results-table {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .table-header {
            background: #f8f9fa;
            padding: 15px 20px;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #e1e5e9;
        }
        
        .results-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .result-item {
            padding: 15px 20px;
            border-bottom: 1px solid #e1e5e9;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        
        .status-online {
            background: #28a745;
        }
        
        .status-offline {
            background: #dc3545;
        }
        
        .status-error {
            background: #ffc107;
        }
        
        .result-info {
            flex: 1;
        }
        
        .result-ip {
            font-weight: 600;
            color: #333;
            font-size: 1.1em;
        }
        
        .result-hostname {
            color: #666;
            font-size: 0.9em;
            margin-top: 2px;
        }
        
        .result-time {
            color: #28a745;
            font-weight: 600;
            font-size: 0.9em;
        }
        
        .result-actions {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .btn-vnc {
            background: linear-gradient(135deg, #17a2b8 0%, #138496 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn-vnc:hover {
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .btn-vnc:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-shutdown {
            background: linear-gradient(135deg, #dc3545 0%, #b02a37 100%);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn-shutdown:hover {
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .btn-shutdown:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #4facfe;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .content {
                padding: 20px;
            }
            
            .stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }
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
                        <input type="text" id="network_range" name="network_range" 
                               value="<?php echo htmlspecialchars(getLocalNetwork()); ?>" 
                               placeholder="192.168.1.1-254">
                        <small style="color: #666; font-size: 0.9em;">
                            Форматы: 192.168.1.1-254 или 192.168.1.1-192.168.1.100
                        </small>
                    </div>

                    <div class="form-group">
                        <label for="source_ip">Сетевой интерфейс (исходный IP):</label>
                        <select id="source_ip" name="source_ip">
                            <option value="">Автовыбор системой</option>
                        </select>
                        <small style="color: #666; font-size: 0.9em;">
                            Можно указать исходный IP для пинга (если поддерживается ОС)
                        </small>
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
                    
                    <button type="submit" class="btn" id="scanBtn">
                        🚀 Начать сканирование
                    </button>
                    <button type="button" class="btn btn-danger" id="stopBtn" style="display: none;">
                        ⛔ Остановить
                    </button>
                    <button type="button" class="btn btn-secondary" id="exportBtn" style="display: none;">
                        📊 Экспорт в CSV
                    </button>
                </form>
            </div>
            
            <div class="progress-section" id="progressSection">
                <div class="progress-bar">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <div class="progress-text" id="progressText">Подготовка к сканированию...</div>
            </div>
            
            <div class="results-section" id="resultsSection" style="display: none;">
                <div class="stats" id="statsContainer"></div>
                <div class="results-table">
                    <div class="table-header">
                        Результаты сканирования
                    </div>
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
        
        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
        
        document.getElementById('exportBtn').addEventListener('click', function() {
            if (scanData) {
                exportToCSV();
            }
        });

        document.getElementById('logRefreshBtn')?.addEventListener('click', refreshLog);
        document.getElementById('logDownloadBtn')?.addEventListener('click', downloadLog);
        
        function startScan() {
            const form = document.getElementById('scanForm');
            const formData = new FormData(form);
            formData.append('action', 'scan');
            
            const scanBtn = document.getElementById('scanBtn');
            const progressSection = document.getElementById('progressSection');
            const resultsSection = document.getElementById('resultsSection');
            const exportBtn = document.getElementById('exportBtn');
            const stopBtn = document.getElementById('stopBtn');
            
            scanBtn.disabled = true;
            scanBtn.textContent = '⏳ Сканирование...';
            progressSection.style.display = 'block';
            resultsSection.style.display = 'none';
            exportBtn.style.display = 'none';
            stopBtn.style.display = 'inline-block';
            stopBtn.disabled = false;
            
            // Потоковый режим через SSE
            startStreamingScan(form);
        }
        
        function startStreamingScan(form) {
            const scanBtn = document.getElementById('scanBtn');
            const progressSection = document.getElementById('progressSection');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            const resultsSection = document.getElementById('resultsSection');
            const resultsList = document.getElementById('resultsList');
            const statsContainer = document.getElementById('statsContainer');
            const exportBtn = document.getElementById('exportBtn');
            const stopBtn = document.getElementById('stopBtn');

            resultsList.innerHTML = '';
            statsContainer.innerHTML = '';
            resultsSection.style.display = 'none';
            progressSection.style.display = 'block';
            progressFill.style.width = '0%';
            progressText.textContent = 'Подготовка к сканированию...';
            exportBtn.style.display = 'none';

            scanData = { results: [], stats: { total: 0, online: 0, offline: 0, errors: 0, scan_time: 0 } };

            const params = new URLSearchParams();
            params.set('action', 'scan_stream');
            params.set('network_range', form.network_range.value);
            params.set('timeout', form.timeout.value);
            params.set('show_offline', form.show_offline.checked ? '1' : '0');
            if (form.source_ip.value) params.set('source_ip', form.source_ip.value);

            if (currentEventSource) { try { currentEventSource.close(); } catch(e){} }
            const es = new EventSource('?' + params.toString());
            currentEventSource = es;

            es.addEventListener('progress', (ev) => {
                try {
                    const payload = JSON.parse(ev.data);
                    const { progress, index, total, counts, result } = payload;
                    progressFill.style.width = progress + '%';
                    progressText.textContent = `Прогресс: ${index}/${total} (${progress}%)`;

                    // Обновляем статистику
                    scanData.stats = { total, online: counts.online, offline: counts.offline, errors: counts.errors, scan_time: 0 };
                    renderStats(scanData.stats);

                    // Добавляем результат, если есть
                    if (result) {
                        scanData.results.push(result);
                        appendResultItem(result);
                        // Автообновление лога во время сканирования (не чаще 1 р/сек)
                        throttleRefreshLog();
                    }
                } catch (e) {
                    // игнорируем парсинг ошибки
                }
            });

            es.addEventListener('done', (ev) => {
                try {
                    const data = JSON.parse(ev.data);
                    scanData = data;
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Готово';
                    renderStats(scanData.stats);
                    // Перерисуем список, чтобы отразить возможные скрытые элементы
                    displayResults(scanData);
                    exportBtn.style.display = 'inline-block';
                    refreshLog();
                } catch (e) {
                    showError('Ошибка обработки завершения сканирования');
                } finally {
                    es.close();
                    if (currentEventSource === es) currentEventSource = null;
                    scanBtn.disabled = false;
                    scanBtn.textContent = '🚀 Начать сканирование';
                    progressSection.style.display = 'none';
                    stopBtn.style.display = 'none';
                }
            });

            es.addEventListener('error', (ev) => {
                try {
                    const data = JSON.parse(ev.data);
                    showError(data.error || 'Ошибка при сканировании');
                } catch (e) {
                    showError('Ошибка при сканировании');
                } finally {
                    es.close();
                    if (currentEventSource === es) currentEventSource = null;
                    scanBtn.disabled = false;
                    scanBtn.textContent = '🚀 Начать сканирование';
                    progressSection.style.display = 'none';
                    stopBtn.style.display = 'none';
                }
            });
        }

        // Кнопка Остановить: закрывает EventSource, UI возвращается в исходное состояние
        document.getElementById('stopBtn')?.addEventListener('click', () => {
            const stopBtn = document.getElementById('stopBtn');
            const scanBtn = document.getElementById('scanBtn');
            stopBtn.disabled = true;
            stopBtn.textContent = '⏹ Остановка...';
            try { if (currentEventSource) currentEventSource.close(); } catch(e) {}
            currentEventSource = null;
            scanBtn.disabled = false;
            scanBtn.textContent = '🚀 Начать сканирование';
            document.getElementById('progressSection').style.display = 'none';
            stopBtn.style.display = 'none';
        });

        function renderStats(stats) {
            const statsContainer = document.getElementById('statsContainer');
            statsContainer.innerHTML = `
                <div class="stat-card total">
                    <div class="stat-number">${stats.total}</div>
                    <div class="stat-label">Всего проверено</div>
                </div>
                <div class="stat-card online">
                    <div class="stat-number">${stats.online}</div>
                    <div class="stat-label">Онлайн</div>
                </div>
                <div class="stat-card offline">
                    <div class="stat-number">${stats.offline}</div>
                    <div class="stat-label">Офлайн</div>
                </div>
                <div class="stat-card errors">
                    <div class="stat-number">${stats.errors}</div>
                    <div class="stat-label">Ошибки</div>
                </div>
            `;
            document.getElementById('resultsSection').style.display = 'block';
        }

        function appendResultItem(result) {
            const resultsList = document.getElementById('resultsList');
            const item = document.createElement('div');
            item.className = 'result-item';
            const hostnameHtml = (result.hostname && result.hostname !== 'Unknown' && result.hostname !== 'N/A') ? 
                `<div class="result-hostname">${result.hostname}</div>` : '';
            const timeHtml = result.response_time ? 
                `<div class="result-time">${result.response_time}мс</div>` : 
                '<div class="result-time">N/A</div>';
            const vncButton = result.status === 'online' ? 
                `<button class="btn-vnc" onclick="connectVNC('${result.ip}')" title="Подключиться через VNC">🖥️ VNC</button>` : 
                `<button class="btn-vnc" disabled title="Компьютер недоступен">🖥️ VNC</button>`;
            const shutdownButton = result.status === 'online' ? 
                `<button class="btn-shutdown" onclick="shutdownComputer('${result.ip}')" title="Выключить компьютер">🔌 Выключить</button>` : 
                `<button class="btn-shutdown" disabled title="Компьютер недоступен">🔌 Выключить</button>`;
            item.innerHTML = `
                <div class="status-indicator status-${result.status}"></div>
                <div class="result-info">
                    <div class="result-ip">${result.ip}</div>
                    ${hostnameHtml}
                </div>
                <div class="result-actions">
                    ${timeHtml}
                    ${vncButton}
                    ${shutdownButton}
                </div>
            `;
            resultsList.appendChild(item);
        }
        function displayResults(data) {
            const resultsSection = document.getElementById('resultsSection');
            const statsContainer = document.getElementById('statsContainer');
            const resultsList = document.getElementById('resultsList');
            
            // Показываем статистику
            statsContainer.innerHTML = `
                <div class="stat-card total">
                    <div class="stat-number">${data.stats.total}</div>
                    <div class="stat-label">Всего проверено</div>
                </div>
                <div class="stat-card online">
                    <div class="stat-number">${data.stats.online}</div>
                    <div class="stat-label">Онлайн</div>
                </div>
                <div class="stat-card offline">
                    <div class="stat-number">${data.stats.offline}</div>
                    <div class="stat-label">Офлайн</div>
                </div>
                <div class="stat-card errors">
                    <div class="stat-number">${data.stats.errors}</div>
                    <div class="stat-label">Ошибки</div>
                </div>
            `;
            
            // Показываем результаты
            if (data.results.length === 0) {
                resultsList.innerHTML = '<div class="loading">Активные компьютеры не найдены</div>';
            } else {
                resultsList.innerHTML = data.results.map(result => {
                    const hostnameHtml = (result.hostname && result.hostname !== 'Unknown' && result.hostname !== 'N/A') ? 
                        `<div class="result-hostname">${result.hostname}</div>` : '';
                    const timeHtml = result.response_time ? 
                        `<div class="result-time">${result.response_time}мс</div>` : 
                        '<div class="result-time">N/A</div>';
                    const vncButton = result.status === 'online' ? 
                        `<button class="btn-vnc" onclick="connectVNC('${result.ip}')" title="Подключиться через VNC">🖥️ VNC</button>` : 
                        `<button class="btn-vnc" disabled title="Компьютер недоступен">🖥️ VNC</button>`;
                    const shutdownButton = result.status === 'online' ? 
                        `<button class="btn-shutdown" onclick="shutdownComputer('${result.ip}')" title="Выключить компьютер">🔌 Выключить</button>` : 
                        `<button class="btn-shutdown" disabled title="Компьютер недоступен">🔌 Выключить</button>`;
                    return `
                        <div class="result-item">
                            <div class="status-indicator status-${result.status}"></div>
                            <div class="result-info">
                                <div class="result-ip">${result.ip}</div>
                                ${hostnameHtml}
                            </div>
                            <div class="result-actions">
                                ${timeHtml}
                                ${vncButton}
                                ${shutdownButton}
                            </div>
                        </div>
                    `;
                }).join('');
            }
            
            resultsSection.style.display = 'block';
        }
        
        function exportToCSV() {
            if (!scanData) return;
            
            const formData = new FormData();
            formData.append('action', 'export');
            formData.append('data', JSON.stringify(scanData));
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'network_scan_' + new Date().toISOString().slice(0,19).replace(/:/g, '-') + '.csv';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            })
            .catch(error => {
                showError('Ошибка при экспорте: ' + error.message);
            });
        }

        let lastLogRefresh = 0;
        function throttleRefreshLog() {
            const now = Date.now();
            if (now - lastLogRefresh > 1000) {
                lastLogRefresh = now;
                refreshLog();
            }
        }

        function refreshLog() {
            const lines = document.getElementById('logLines')?.value || '200';
            const body = new URLSearchParams({ action: 'log_tail', lines });
            fetch('', { method: 'POST', body })
                .then(r => r.json())
                .then(data => {
                    const viewer = document.getElementById('logViewer');
                    if (viewer && data && typeof data.text === 'string') {
                        viewer.textContent = data.text;
                        viewer.scrollTop = viewer.scrollHeight;
                    }
                })
                .catch(() => {});
        }

        function downloadLog() {
            const body = new URLSearchParams({ action: 'log_download' });
            fetch('', { method: 'POST', body })
                .then(r => r.blob())
                .then(blob => {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'network_scan.log';
                    document.body.appendChild(a);
                    a.click();
                    URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                })
                .catch(() => {});
        }
        
        function connectVNC(ip) {
            // В PHP версии используем внешний VNC клиент
            const formData = new FormData();
            formData.append('action', 'vnc_connect');
            formData.append('ip', ip);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('VNC клиент запущен для ' + ip + '\\n\\nЕсли клиент не открылся, установите TightVNC, UltraVNC или RealVNC.');
                } else {
                    alert('Ошибка запуска VNC клиента для ' + ip + ':\\n' + (data.error || 'Неизвестная ошибка'));
                }
            })
            .catch(error => {
                alert('Ошибка запуска VNC клиента для ' + ip + ':\\n' + error.message);
            });
        }
        
        function shutdownComputer(ip) {
            if (!confirm(`Вы уверены, что хотите выключить компьютер ${ip}?\n\nЭто действие нельзя отменить!`)) {
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
                    alert(`Команда выключения отправлена на ${ip}\n\n${data.message || 'Компьютер будет выключен через несколько секунд.'}`);
                    logEvent('SHUTDOWN', { ip: ip, success: true });
                } else {
                    alert(`Ошибка при выключении ${ip}:\n${data.error || 'Неизвестная ошибка'}`);
                    logEvent('SHUTDOWN', { ip: ip, success: false, error: data.error });
                }
            })
            .catch(error => {
                alert(`Ошибка при выключении ${ip}:\n${error.message}`);
                logEvent('SHUTDOWN', { ip: ip, success: false, error: error.message });
            });
        }
        
        function showError(message) {
            const resultsSection = document.getElementById('resultsSection');
            resultsSection.innerHTML = `
                <div class="alert alert-error">
                    <strong>Ошибка:</strong> ${message}
                </div>
            `;
            resultsSection.style.display = 'block';
        }

        // Загрузка интерфейсов при старте
        document.addEventListener('DOMContentLoaded', () => {
            fetch('', {
                method: 'POST',
                body: new URLSearchParams({ action: 'interfaces' })
            })
            .then(r => r.json())
            .then(data => {
                const select = document.getElementById('source_ip');
                if (data && Array.isArray(data.interfaces)) {
                    data.interfaces.forEach(iface => {
                        const opt = document.createElement('option');
                        opt.value = iface.ip;
                        opt.textContent = `${iface.name} — ${iface.ip}`;
                        select.appendChild(opt);
                    });
                }
            })
            .catch(() => {/* ignore */});

            // Загрузим лог при старте
            refreshLog();
        });
    </script>
</body>
</html>
