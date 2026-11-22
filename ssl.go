package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- Константы и типы ----------

const (
	sslBudget        = 1200 * time.Millisecond // DNS + TCP + handshake, суммарно
	sslMaxConcurrent = 32                      // максимум одновременных исходящих проб
	sslCacheMax      = 20000                   // жёсткая граница памяти
	sslMaxScore      = 35                      // < phishingThreshold: SSL не решает вердикт сам
)

type SSLStatus string

const (
	SSLOK      SSLStatus = "ok"      // сертификат валиден
	SSLInvalid SSLStatus = "invalid" // сертификат есть, но не прошёл проверку
	SSLNoTLS   SSLStatus = "no_tls"  // 443 закрыт / там не TLS
	SSLNoDNS   SSLStatus = "no_dns"  // домен не резолвится
	SSLUnknown SSLStatus = "unknown" // не успели / не смогли — БЕЗ штрафа
	SSLSkipped SSLStatus = "skipped" // не проверяли (лимит, IP, отмена)
	SSLBlocked SSLStatus = "blocked" // приватный адрес (SSRF)
)

type SSLReport struct {
	Status      SSLStatus `json:"status"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   string    `json:"not_before,omitempty"`
	NotAfter    string    `json:"not_after,omitempty"`
	CertAgeDays int       `json:"cert_age_days,omitempty"`
	ElapsedMS   int64     `json:"elapsed_ms"`
	Notes       []string  `json:"notes,omitempty"`  // информация без баллов
	Detail      string    `json:"detail,omitempty"` // техническая причина
	Score       int       `json:"-"`
	Reasons     []string  `json:"-"`
	checkedAt   time.Time
	ttl         time.Duration
}

func (r SSLReport) cacheTTL() time.Duration {
	switch r.Status {
	case SSLOK:
		return 30 * time.Minute
	case SSLInvalid:
		return 10 * time.Minute
	case SSLNoTLS:
		return 2 * time.Minute
	case SSLNoDNS:
		return 5 * time.Minute
	case SSLBlocked:
		return time.Minute
	case SSLUnknown:
		return 15 * time.Second // чтобы не долбить недоступный хост
	default:
		return 0 // skipped не кэшируем: это наше состояние, а не свойство хоста
	}
}

// ---------- Метрики (atomic-счётчики, легко экспортируются в Prometheus) ----------

var (
	sslMetricsHits      atomic.Int64
	sslMetricsMisses    atomic.Int64
	sslMetricsFlights   atomic.Int64 // сколько раз попали в single-flight
	sslMetricsOK        atomic.Int64
	sslMetricsInvalid   atomic.Int64
	sslMetricsNoTLS     atomic.Int64
	sslMetricsNoDNS     atomic.Int64
	sslMetricsBlocked   atomic.Int64
	sslMetricsUnknown   atomic.Int64
	sslMetricsSkipped   atomic.Int64
	sslMetricsErrors    atomic.Int64
	sslMetricsLatencyMs atomic.Int64 // сумма задержек для среднего
	sslMetricsSamples   atomic.Int64 // количество сэмплов
)

// SSLMetrics возвращает снимок метрик (для Prometheus-экспортера или отладки).
func SSLMetrics() map[string]int64 {
	return map[string]int64{
		"ssl_hits":       sslMetricsHits.Load(),
		"ssl_misses":     sslMetricsMisses.Load(),
		"ssl_flights":    sslMetricsFlights.Load(),
		"ssl_ok":         sslMetricsOK.Load(),
		"ssl_invalid":    sslMetricsInvalid.Load(),
		"ssl_no_tls":     sslMetricsNoTLS.Load(),
		"ssl_no_dns":     sslMetricsNoDNS.Load(),
		"ssl_blocked":    sslMetricsBlocked.Load(),
		"ssl_unknown":    sslMetricsUnknown.Load(),
		"ssl_skipped":    sslMetricsSkipped.Load(),
		"ssl_errors":     sslMetricsErrors.Load(),
		"ssl_latency_ms": sslMetricsLatencyMs.Load(),
		"ssl_samples":    sslMetricsSamples.Load(),
	}
}

// ---------- Single-flight + LRU-кэш ----------

type sslCall struct {
	done   chan struct{}
	report SSLReport
}

type lruEntry struct {
	host   string
	report SSLReport
}

var (
	sslMu      sync.Mutex
	sslCache   = make(map[string]*list.Element)
	sslLru     = list.New() // front = MRU, back = LRU
	sslFlights = make(map[string]*sslCall)
	sslSlots   = make(chan struct{}, sslMaxConcurrent)
)

// ---------- Корневые сертификаты (инициализация один раз через sync.Once) ----------

var (
	rootsPool  *x509.CertPool
	rootsOnce  sync.Once
	rootsReady bool
)

func rootCAs() *x509.CertPool {
	rootsOnce.Do(func() {
		p, err := x509.SystemCertPool()
		if err != nil || p == nil {
			log.Printf("SSL: системное хранилище корневых сертификатов недоступно (%v)", err)
			return
		}
		rootsPool = p
		rootsReady = true
	})
	if !rootsReady {
		return nil
	}
	return rootsPool
}

// ---------- normalizeHost ----------

// ---------- checkSSL: кэш → single-flight → проба ----------

func checkSSL(ctx context.Context, host string) SSLReport {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start).Milliseconds()
		sslMetricsLatencyMs.Add(elapsed)
		sslMetricsSamples.Add(1)
	}()

	host, err := normalizeHost(host)
	if err != nil || host == "" || net.ParseIP(host) != nil {
		sslMetricsSkipped.Add(1)
		return SSLReport{Status: SSLSkipped, Detail: "некорректное имя или IP-литерал"}
	}
	if err := ctx.Err(); err != nil {
		sslMetricsSkipped.Add(1)
		return SSLReport{Status: SSLSkipped, Detail: "проверка отменена до запуска: " + err.Error()}
	}

	sslMu.Lock()
	// 1) Кэш
	if el, ok := sslCache[host]; ok {
		entry := el.Value.(*lruEntry)
		if time.Since(entry.report.checkedAt) < entry.report.ttl {
			sslLru.MoveToFront(el)
			rep := entry.report
			sslMu.Unlock()
			sslMetricsHits.Add(1)
			return rep
		}
		// протухло — удаляем
		sslLru.Remove(el)
		delete(sslCache, host)
	}
	// 2) Single-flight
	if call, ok := sslFlights[host]; ok {
		sslMu.Unlock()
		sslMetricsFlights.Add(1)
		select {
		case <-call.done:
			return call.report
		case <-ctx.Done():
			sslMetricsSkipped.Add(1)
			return SSLReport{Status: SSLSkipped, Detail: "ожидание пробы отменено"}
		}
	}
	call := &sslCall{done: make(chan struct{})}
	sslFlights[host] = call
	sslMu.Unlock()
	sslMetricsMisses.Add(1)

	report := probeTLS(ctx, host)
	cancelled := ctx.Err() != nil
	if cancelled {
		report = SSLReport{Status: SSLSkipped, Detail: "контекст запроса отменён: " + ctx.Err().Error()}
	}
	report.checkedAt = time.Now()
	report.ttl = report.cacheTTL()

	// учтём статус в метриках
	switch report.Status {
	case SSLOK:
		sslMetricsOK.Add(1)
	case SSLInvalid:
		sslMetricsInvalid.Add(1)
	case SSLNoTLS:
		sslMetricsNoTLS.Add(1)
	case SSLNoDNS:
		sslMetricsNoDNS.Add(1)
	case SSLBlocked:
		sslMetricsBlocked.Add(1)
	case SSLUnknown:
		sslMetricsUnknown.Add(1)
	case SSLSkipped:
		sslMetricsSkipped.Add(1)
	}

	sslMu.Lock()
	call.report = report
	delete(sslFlights, host)
	if report.ttl > 0 && !cancelled {
		// вставляем/обновляем в LRU
		if el, ok := sslCache[host]; ok {
			entry := el.Value.(*lruEntry)
			entry.report = report
			sslLru.MoveToFront(el)
		} else {
			entry := &lruEntry{host: host, report: report}
			el := sslLru.PushFront(entry)
			sslCache[host] = el
		}
		// вытеснение по размеру
		for sslLru.Len() > sslCacheMax {
			back := sslLru.Back()
			if back == nil {
				break
			}
			entry := back.Value.(*lruEntry)
			sslLru.Remove(back)
			delete(sslCache, entry.host)
		}
	}
	sslMu.Unlock()

	close(call.done)
	return report
}

// ---------- probeTLS ----------

func probeTLS(ctx context.Context, host string) (rep SSLReport) {
	select {
	case sslSlots <- struct{}{}:
		defer func() { <-sslSlots }()
	case <-ctx.Done():
		return SSLReport{Status: SSLSkipped, Detail: "ожидание свободного слота отменено"}
	}

	ctx, cancel := context.WithTimeout(ctx, sslBudget)
	defer cancel()

	start := time.Now()
	defer func() { rep.ElapsedMS = time.Since(start).Milliseconds() }()

	conn, err := dialPublicTCP(ctx, host, "443")
	if err != nil {
		sslMetricsErrors.Add(1)
		return classifyNetError(err)
	}
	defer conn.Close()

	// InsecureSkipVerify здесь осознанный: валидацию делаем вручную ниже,
	// чтобы получить и разобрать даже невалидный сертификат.
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tconn.HandshakeContext(ctx); err != nil {
		sslMetricsErrors.Add(1)
		return classifyNetError(err)
	}

	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return SSLReport{Status: SSLUnknown, Detail: "сервер не прислал сертификат"}
	}

	leaf := certs[0]
	rep.Status = SSLOK
	rep.Issuer = leaf.Issuer.CommonName
	rep.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	rep.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	rep.CertAgeDays = int(time.Since(leaf.NotBefore).Hours() / 24)

	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}

	roots := rootCAs()
	if roots == nil {
		// Не выдаём SSLOK, если цепочку доверия невозможно проверить.
		// Иначе самоподписанный сертификат мог бы считаться валидным.
		rep.Status = SSLUnknown
		rep.Detail = "системное хранилище корневых сертификатов недоступно"
		return rep
	}

	_, verifyErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   time.Now(),
	})
	if verifyErr != nil {
		rep.Status = SSLInvalid
		rep.Detail = verifyErr.Error()
		var hostErr x509.HostnameError
		var certErr x509.CertificateInvalidError
		var authErr x509.UnknownAuthorityError
		switch {
		case errors.As(verifyErr, &hostErr):
			rep.Score = 30
			rep.Reasons = append(rep.Reasons, "TLS-сертификат не соответствует имени хоста (CN/SAN mismatch).")
		case errors.As(verifyErr, &certErr) && certErr.Reason == x509.Expired:
			rep.Score = 25
			rep.Reasons = append(rep.Reasons, "TLS-сертификат просрочен или ещё не вступил в силу.")
		case errors.As(verifyErr, &authErr):
			rep.Score = 10
			rep.Reasons = append(rep.Reasons, "Цепочка доверия не построена: самоподписанный сертификат либо сервер не отдаёт промежуточный.")
		default:
			rep.Score = 15
			rep.Reasons = append(rep.Reasons, "TLS-сертификат не прошёл проверку: "+verifyErr.Error())
		}
	}

	// Только информация, без баллов: у Let's Encrypt сертификат моложе 7 дней
	// примерно у четверти честных сайтов в любой момент времени.
	if age := time.Since(leaf.NotBefore); age >= 0 && age < 7*24*time.Hour {
		rep.Notes = append(rep.Notes, fmt.Sprintf(
			"Сертификат выпущен %s (%d дн. назад). Само по себе не признак фишинга: короткие сроки — норма для ACME/CA.",
			leaf.NotBefore.Format("02.01.2006"), rep.CertAgeDays))
	}
	if left := time.Until(leaf.NotAfter); left > 0 && left < 3*24*time.Hour {
		rep.Notes = append(rep.Notes, "Сертификат истекает менее чем через 3 дня (вероятно, не настроено автопродление).")
	}

	if rep.Score > sslMaxScore {
		rep.Score = sslMaxScore
	}
	return rep
}

// ---------- Классификация сетевых ошибок ----------

// WSAECONNREFUSED: на Windows net.Dial возвращает именно этот код,
// а errors.Is(err, syscall.ECONNREFUSED) там не срабатывает (golang/go#45621).
const wsaConnRefused = syscall.Errno(10061)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaConnRefused)
}

func classifyNetError(err error) SSLReport {
	var dnsErr *net.DNSError
	var recErr *tls.RecordHeaderError // указатель — обязательно для errors.As
	switch {
	case errors.Is(err, errPrivateAddr):
		return SSLReport{Status: SSLBlocked,
			Detail: "хост резолвится в приватный/служебный адрес — проверка запрещена"}
	case isConnRefused(err):
		return SSLReport{Status: SSLNoTLS, Score: 5,
			Reasons: []string{"Порт 443 закрыт (connection refused)."},
			Detail:  err.Error()}
	case errors.As(err, &recErr):
		// Сервер вернул что-то, не похожее на TLS-запись (часто HTTP на 443).
		return SSLReport{Status: SSLNoTLS, Score: 5,
			Reasons: []string{"Порт 443 открыт, но там не TLS (сайт работает только по HTTP)."},
			Detail:  err.Error()}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return SSLReport{Status: SSLNoDNS, Score: 10,
			Reasons: []string{"Домен не резолвится: не существует или снят с делегирования."},
			Detail:  err.Error()}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), isTimeoutErr(err):
		return SSLReport{Status: SSLUnknown,
			Detail: "не успели проверить за отведённый бюджет: " + err.Error()}
	default:
		return SSLReport{Status: SSLUnknown, Detail: err.Error()}
	}
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// ---------- SSRF-guard ----------

var errPrivateAddr = errors.New("приватный или служебный IP-адрес")

// Убраны префиксы, которые не являются приватными и могут блокировать легитимные адреса:
//   - 64:ff9b::/96 (NAT64)
//   - 2001::/23    (IETF protocol assignments, не приватный)
//   - 2002::/16    (6to4, глобально маршрутизируемый)
var blockedNets = mustParseCIDRs([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	"2001:db8::/32", // documentation prefix
})

func mustParseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("bad CIDR " + s + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

func isPublicAddr(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		!ip.IsGlobalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// ---------- Happy Eyeballs (RFC 8305) для dialPublicTCP ----------

// dialPublicTCP резолвит хост сам и коннектится к уже проверенному IP,
// чтобы между проверкой и соединением не было окна для DNS rebinding.
// Использует Happy Eyeballs: IPv6 стартует сразу, IPv4 — с задержкой,
// побеждает первый установивший соединение.
func dialPublicTCP(ctx context.Context, host, port string) (net.Conn, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var ipv4, ipv6 []net.IPAddr
	var blocked bool
	for _, a := range addrs {
		if !isPublicAddr(a.IP) {
			blocked = true
			continue
		}
		if a.IP.To4() != nil {
			ipv4 = append(ipv4, a)
		} else {
			ipv6 = append(ipv6, a)
		}
	}

	if len(ipv4) == 0 && len(ipv6) == 0 {
		if blocked {
			return nil, errPrivateAddr
		}
		return nil, fmt.Errorf("у хоста %s нет подходящих IP-адресов", host)
	}

	type result struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan result, len(ipv4)+len(ipv6))

	d := &net.Dialer{Timeout: sslBudget}

	dialOne := func(addr net.IPAddr) {
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.IP.String(), port))
		resCh <- result{c, err}
	}

	// Запускаем IPv6 сразу
	for _, a := range ipv6 {
		go dialOne(a)
	}

	// IPv4 — с задержкой 200ms (RFC 8305)
	if len(ipv4) > 0 {
		go func() {
			select {
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			for _, a := range ipv4 {
				go dialOne(a)
			}
		}()
	}

	// Ждём первый успешный результат или исчерпания попыток
	pending := len(ipv4) + len(ipv6)
	var lastErr error
	for pending > 0 {
		select {
		case r := <-resCh:
			pending--
			if r.err == nil && r.conn != nil {
				return r.conn, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	if blocked {
		return nil, errPrivateAddr
	}
	return nil, fmt.Errorf("у хоста %s нет подходящих IP-адресов", host)
}
