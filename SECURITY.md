# 🔒 Политика безопасности

## 🚨 Сообщение об уязвимостях

Мы серьезно относимся к безопасности Network Scanner. Если вы обнаружили уязвимость безопасности, пожалуйста, сообщите об этом ответственно.

### 📧 Как сообщить

**НЕ создавайте публичные GitHub issues для уязвимостей безопасности.**

Вместо этого:

1. **Отправьте email** на security@example.com с подробным описанием
2. **Или используйте** GitHub Security Advisories (если доступно)
3. **Включите** следующую информацию:
   - Описание уязвимости
   - Шаги для воспроизведения
   - Потенциальное воздействие
   - Предлагаемые исправления (если есть)

### ⏱️ Временные рамки ответа

- **Подтверждение получения**: в течение 48 часов
- **Первоначальная оценка**: в течение 7 дней
- **Исправление**: зависит от серьезности (1-90 дней)

### 🏆 Программа вознаграждений

В настоящее время у нас нет программы вознаграждений за обнаружение уязвимостей, но мы ценим ваш вклад и будем признательны за помощь в улучшении безопасности проекта.

## ⚠️ Известные уязвимости

### Отсутствие аутентификации

**Серьезность**: Высокая  
**Статус**: Известная проблема  
**Описание**: Network Scanner не имеет встроенной аутентификации

**Рекомендации**:
- Используйте reverse proxy (nginx, Apache) с аутентификацией
- Ограничьте доступ через файрвол
- Используйте только в доверенных сетях

### Отсутствие валидации входных данных

**Серьезность**: Средняя  
**Статус**: Частично исправлено  
**Описание**: Некоторые входные данные не полностью валидируются

**Исправления**:
- Добавлена базовая валидация IP адресов
- Санитизация HTML в выводе
- Ограничение длины входных строк

### Отсутствие HTTPS

**Серьезность**: Средняя  
**Статус**: Планируется  
**Описание**: По умолчанию используется HTTP

**Рекомендации**:
- Используйте reverse proxy с SSL/TLS
- Настройте Let's Encrypt сертификаты
- Принудительное перенаправление на HTTPS

## 🛡️ Рекомендации по безопасности

### Развертывание

#### 1. Сетевая безопасность
```bash
# Ограничение доступа через файрвол
ufw allow from 192.168.1.0/24 to any port 8080
ufw deny 8080

# Или через iptables
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

#### 2. Reverse Proxy с аутентификацией
```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name scanner.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # Базовая аутентификация
    auth_basic "Network Scanner";
    auth_basic_user_file /path/to/.htpasswd;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 3. Docker с ограничениями
```dockerfile
# Создание непривилегированного пользователя
FROM golang:1.21-alpine AS builder
# ... build steps ...

FROM alpine:latest
RUN adduser -D -s /bin/sh scanner
USER scanner
WORKDIR /home/scanner
COPY --from=builder /app/scanner .
EXPOSE 8080
CMD ["./scanner"]
```

### Конфигурация

#### 1. Переменные окружения
```bash
# Ограничение доступа
export ADDR="127.0.0.1:8080"  # Только локальный доступ

# Или через файрвол
export ADDR="0.0.0.0:8080"    # Все интерфейсы + файрвол
```

#### 2. Права доступа к файлам
```bash
# Ограничение прав на лог файлы
chmod 600 network_scan.log
chown scanner:scanner network_scan.log

# Права на исполняемые файлы
chmod 755 scanner
chown scanner:scanner scanner
```

### Мониторинг

#### 1. Логирование безопасности
```go
// Добавление в код
func logSecurityEvent(event string, details map[string]interface{}) {
    logEvent("security", map[string]interface{}{
        "event": event,
        "details": details,
        "timestamp": time.Now().Format(time.RFC3339),
        "ip": getClientIP(),
    })
}
```

#### 2. Мониторинг доступа
```bash
# Мониторинг логов доступа
tail -f /var/log/nginx/access.log | grep scanner

# Алерты на подозрительную активность
grep "401\|403\|404" /var/log/nginx/access.log | mail -s "Security Alert" admin@example.com
```

## 🔐 Шифрование и хранение данных

### Логи
- Логи содержат потенциально чувствительную информацию
- Рекомендуется шифрование лог файлов
- Регулярная ротация и архивирование

### VNC пароли
- Пароли передаются в открытом виде через WebSocket
- Рекомендуется использование VPN или защищенных соединений
- Рассмотрите возможность использования токенов вместо паролей

### Сетевая информация
- IP адреса и hostname могут быть чувствительными
- Ограничьте доступ к результатам сканирования
- Не сохраняйте результаты в незащищенных местах

## 🚫 Ограничения использования

### Правовые аспекты
- Используйте только в собственных сетях или с явного разрешения
- Соблюдайте местные законы о кибербезопасности
- Не используйте для несанкционированного доступа

### Этические принципы
- Получайте разрешение перед сканированием чужих сетей
- Не используйте для вредоносных целей
- Уважайте приватность других пользователей

## 🔄 Обновления безопасности

### Регулярные обновления
- Следите за обновлениями зависимостей
- Регулярно обновляйте Go runtime
- Мониторьте уязвимости в используемых библиотеках

### Проверка зависимостей
```bash
# Проверка уязвимостей в Go модулях
go list -json -m all | nancy sleuth

# Или через govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## 📞 Контакты по безопасности

- **Email**: security@example.com
- **PGP**: [Ключ для шифрования](https://example.com/pgp-key.txt)
- **GitHub Security**: [Security Advisories](https://github.com/yourusername/Network-Scanner/security/advisories)

## 📚 Дополнительные ресурсы

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Best Practices](https://golang.org/doc/security.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)

---

**Помните**: Безопасность - это общая ответственность. Помогите нам сделать Network Scanner более безопасным!
