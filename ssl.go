package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

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

	Score   int      `json:"-"`
	Reasons []string `json:"-"`

	checkedAt time.Time
	ttl       time.Duration
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

type sslCall struct {
	done   chan struct{}
	report SSLReport
}

var (
	sslMu      sync.Mutex
	sslCache   = make(map[string]SSLReport)
	sslFlights = make(map[string]*sslCall)
	sslSlots   = make(chan struct{}, sslMaxConcurrent)

	rootsOnce sync.Once
	rootsPool *x509.CertPool
)

func rootCAs() *x509.CertPool {
	rootsOnce.Do(func() {
		p, err := x509.SystemCertPool()
		if err != nil {
			log.Printf("SSL: системные корневые сертификаты недоступны (%v); "+
				"проверяю только имя и срок. В Docker-образе нужен пакет ca-certificates.", err)
			return
		}
		rootsPool = p
	})
	return rootsPool
}

// checkSSL — единственная точка входа: кэш → single-flight → проба.
func checkSSL(ctx context.Context, host string) SSLReport {
	if host == "" || net.ParseIP(host) != nil {
		return SSLReport{Status: SSLSkipped, Detail: "IP-литерал, TLS-имя не проверяется"}
	}

	sslMu.Lock()
	if cached, ok := sslCache[host]; ok && time.Since(cached.checkedAt) < cached.ttl {
		sslMu.Unlock()
		return cached
	}
	if call, ok := sslFlights[host]; ok { // такую пробу уже выполняют
		sslMu.Unlock()
		select {
		case <-call.done:
			return call.report
		case <-ctx.Done():
			return SSLReport{Status: SSLSkipped, Detail: "ожидание пробы отменено"}
		}
	}
	call := &sslCall{done: make(chan struct{})}
	sslFlights[host] = call
	sslMu.Unlock()

	report := probeTLS(ctx, host)
	report.checkedAt = time.Now()
	report.ttl = report.cacheTTL()

	sslMu.Lock()
	call.report = report
	delete(sslFlights, host)
	if report.ttl > 0 {
		sslCache[host] = report
		if len(sslCache) > sslCacheMax {
			evictSSLLocked()
		}
	}
	sslMu.Unlock()
	close(call.done)

	return report
}

func evictSSLLocked() {
	now := time.Now()
	for h, r := range sslCache {
		if now.Sub(r.checkedAt) >= r.ttl {
			delete(sslCache, h)
		}
	}
	if len(sslCache) <= sslCacheMax {
		return
	}
	target := sslCacheMax - sslCacheMax/10
	for h := range sslCache { // порядок обхода map случаен → дешёвая псевдослучайная вытеснялка
		delete(sslCache, h)
		if len(sslCache) <= target {
			break
		}
	}
}

func probeTLS(ctx context.Context, host string) (rep SSLReport) {
	select {
	case sslSlots <- struct{}{}:
		defer func() { <-sslSlots }()
	default:
		return SSLReport{Status: SSLSkipped, Detail: "лимит параллельных SSL-проверок"}
	}

	ctx, cancel := context.WithTimeout(ctx, sslBudget)
	defer cancel()

	start := time.Now()
	defer func() { rep.ElapsedMS = time.Since(start).Milliseconds() }()

	conn, err := dialPublicTCP(ctx, host, "443")
	if err != nil {
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

	var verifyErr error
	if roots := rootCAs(); roots != nil {
		_, verifyErr = leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: inter,
			CurrentTime:   time.Now(),
		})
	} else {
		// Нет системного хранилища корней — проверяем хотя бы имя и срок.
		if err := leaf.VerifyHostname(host); err != nil {
			verifyErr = err
		} else if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			verifyErr = x509.CertificateInvalidError{Cert: leaf, Reason: x509.Expired}
		}
	}

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
	if age := time.Since(leaf.NotBefore); age < 7*24*time.Hour {
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

// WSAECONNREFUSED: на Windows net.Dial возвращает именно этот код,
// а errors.Is(err, syscall.ECONNREFUSED) там не срабатывает (golang/go#45621).
const wsaConnRefused = syscall.Errno(10061)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaConnRefused)
}

func classifyNetError(err error) SSLReport {
	var dnsErr *net.DNSError
	var recErr tls.RecordHeaderError

	switch {
	case errors.Is(err, errPrivateAddr):
		return SSLReport{Status: SSLBlocked,
			Detail: "хост резолвится в приватный/служебный адрес — проверка запрещена"}

	case isConnRefused(err), errors.As(err, &recErr):
		return SSLReport{Status: SSLNoTLS, Score: 5,
			Reasons: []string{"Порт 443 закрыт или на нём не TLS (сайт работает только по HTTP)."},
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

// ---------- SSRF-guard (используется и в whois.go) ----------

var errPrivateAddr = errors.New("приватный или служебный IP-адрес")

var blockedNets = mustParseCIDRs([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	"64:ff9b::/96", "2001:db8::/32",
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
		ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
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

// Резолвим сами и коннектимся к уже проверенному IP:
// между проверкой и соединением нет окна для DNS rebinding.
func dialPublicTCP(ctx context.Context, host, port string) (net.Conn, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: sslBudget}

	var lastErr error
	blocked := false
	for _, a := range addrs {
		if !isPublicAddr(a.IP) {
			blocked = true
			continue
		}
		conn, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(a.IP.String(), port))
		if derr != nil {
			lastErr = derr
			continue
		}
		return conn, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if blocked {
		return nil, errPrivateAddr
	}
	return nil, fmt.Errorf("у хоста %s нет подходящих IP-адресов", host)
}
