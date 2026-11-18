package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	whoisBudget     = 8 * time.Second         // общий бюджет на всю цепочку
	whoisHopTimeout = 3 * time.Second         // на один запрос
	whoisMaxConcur  = 4                       // параллельных проб
	whoisMinGap     = 1500 * time.Millisecond // вежливый интервал к одному серверу
	whoisCacheMax   = 20000
	whoisMaxScore   = 40  // < 60: WHOIS не выносит вердикт в одиночку
	whoisOldBonus   = -10 // старый домен снижает оценку

	rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"
	rdapCacheFile    = "rdap_bootstrap.json"
)

type DomainStatus string

const (
	DomainOK       DomainStatus = "ok"
	DomainNotFound DomainStatus = "not_found"
	DomainLimited  DomainStatus = "limited" // rate limit реестра
	DomainUnknown  DomainStatus = "unknown"
	DomainSkipped  DomainStatus = "skipped"
)

// domainRecord — сырые данные в кэше. Score/Reasons считаем при каждом чтении,
// чтобы возраст домена не «застывал» на момент первой проверки.
type domainRecord struct {
	Status    DomainStatus
	Created   time.Time
	Expires   time.Time
	Registrar string
	Statuses  []string
	Source    string
	Detail    string
	ElapsedMS int64
	fetchedAt time.Time
	ttl       time.Duration
}

func (r domainRecord) cacheTTL() time.Duration {
	switch r.Status {
	case DomainOK:
		return 24 * time.Hour
	case DomainNotFound:
		return 6 * time.Hour
	case DomainLimited:
		return 15 * time.Minute
	case DomainUnknown:
		return 30 * time.Minute
	default:
		return 0
	}
}

// DomainInfo — то, что уходит фронтенду.
type DomainInfo struct {
	Domain         string   `json:"domain"`
	Status         string   `json:"status"`
	Created        string   `json:"created,omitempty"`
	Expires        string   `json:"expires,omitempty"`
	AgeDays        int      `json:"age_days"` // без omitempty: 0 дней — самый опасный кейс
	Registrar      string   `json:"registrar,omitempty"`
	RegistryStatus []string `json:"registry_status,omitempty"`
	Source         string   `json:"source,omitempty"`
	Notes          []string `json:"notes,omitempty"`
	Detail         string   `json:"detail,omitempty"`
	ElapsedMS      int64    `json:"elapsed_ms"`
	Cached         bool     `json:"cached,omitempty"`
	Score          int      `json:"score"`
	Reasons        []string `json:"reasons"`
}

type whoisCall struct {
	done chan struct{}
	rec  domainRecord
}

var (
	whoisMu     sync.Mutex
	whoisCache  = make(map[string]domainRecord)
	whoisFlight = make(map[string]*whoisCall)
	whoisLast   = make(map[string]time.Time)
	whoisSlots  = make(chan struct{}, whoisMaxConcur)

	rdapMu   sync.RWMutex
	rdapBase = make(map[string]string)

	// Валидация параметра ?domain= : заодно закрывает CRLF-инъекцию в протокол WHOIS.
	domainRegex = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

	whoisServers = map[string]string{
		"ru": "whois.tcinet.ru", "xn--p1ai": "whois.tcinet.ru",
		"su":  "whois.registry.tcinet.ru",
		"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
		"cc": "ccwhois.verisign-grs.com", "tv": "tvwhois.verisign-grs.com",
		"org": "whois.publicinterestregistry.org", "info": "whois.afilias.net",
		"biz": "whois.nic.biz", "io": "whois.nic.io", "me": "whois.nic.me",
		"co": "whois.nic.co", "xyz": "whois.nic.xyz", "top": "whois.nic.top",
		"icu": "whois.nic.icu", "app": "whois.nic.google", "dev": "whois.nic.google",
	}

	rdapClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialPublicTCP(ctx, host, port) // SSRF-guard из ssl.go
			},
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:    16,
			IdleConnTimeout: 30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("слишком много редиректов")
			}
			if req.URL.Scheme != "https" {
				return errors.New("редирект на не-HTTPS")
			}
			return nil
		},
	}
)

func validDomain(d string) bool {
	return len(d) <= 253 && net.ParseIP(d) == nil && domainRegex.MatchString(d)
}

// ---------- кэш + single-flight ----------

func checkDomain(ctx context.Context, domain string) DomainInfo {
	if !validDomain(domain) {
		return buildDomainInfo(domain, domainRecord{Status: DomainSkipped, Detail: "некорректный или IDN-домен"}, false)
	}

	whoisMu.Lock()
	if rec, ok := whoisCache[domain]; ok && time.Since(rec.fetchedAt) < rec.ttl {
		whoisMu.Unlock()
		return buildDomainInfo(domain, rec, true)
	}
	if call, ok := whoisFlight[domain]; ok {
		whoisMu.Unlock()
		select {
		case <-call.done:
			return buildDomainInfo(domain, call.rec, true)
		case <-ctx.Done():
			return buildDomainInfo(domain, domainRecord{Status: DomainSkipped, Detail: "ожидание отменено"}, false)
		}
	}
	call := &whoisCall{done: make(chan struct{})}
	whoisFlight[domain] = call
	whoisMu.Unlock()

	rec := probeDomain(ctx, domain)
	rec.fetchedAt = time.Now()
	rec.ttl = rec.cacheTTL()

	whoisMu.Lock()
	call.rec = rec
	delete(whoisFlight, domain)
	if rec.ttl > 0 {
		whoisCache[domain] = rec
		if len(whoisCache) > whoisCacheMax {
			evictWhoisLocked()
		}
	}
	whoisMu.Unlock()
	close(call.done)

	return buildDomainInfo(domain, rec, false)
}

func evictWhoisLocked() {
	now := time.Now()
	for d, r := range whoisCache {
		if now.Sub(r.fetchedAt) >= r.ttl {
			delete(whoisCache, d)
		}
	}
	if len(whoisCache) <= whoisCacheMax {
		return
	}
	target := whoisCacheMax - whoisCacheMax/10
	for d := range whoisCache {
		delete(whoisCache, d)
		if len(whoisCache) <= target {
			break
		}
	}
}

func probeDomain(ctx context.Context, domain string) domainRecord {
	select {
	case whoisSlots <- struct{}{}:
		defer func() { <-whoisSlots }()
	case <-ctx.Done():
		return domainRecord{Status: DomainSkipped, Detail: "ожидание слота отменено"}
	}

	ctx, cancel := context.WithTimeout(ctx, whoisBudget)
	defer cancel()
	start := time.Now()

	tld := domain[strings.LastIndex(domain, ".")+1:]
	var rdapErr error

	if base := rdapBaseFor(tld); base != "" {
		rec, err := probeRDAP(ctx, base, domain)
		if err == nil {
			rec.ElapsedMS = time.Since(start).Milliseconds()
			return rec
		}
		rdapErr = err
	}

	rec, err := probeWHOIS(ctx, domain)
	rec.ElapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		detail := err.Error()
		if rdapErr != nil {
			detail = "rdap: " + rdapErr.Error() + "; whois: " + detail
		}
		return domainRecord{Status: DomainUnknown, Source: "whois", ElapsedMS: rec.ElapsedMS, Detail: detail}
	}
	return rec
}

// ---------- RDAP ----------

type rdapDoc struct {
	Status []string `json:"status"`
	Events []struct {
		EventAction string `json:"eventAction"`
		EventDate   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles      []string `json:"roles"`
		VCardArray []any    `json:"vcardArray"`
	} `json:"entities"`
}

func probeRDAP(ctx context.Context, base, domain string) (domainRecord, error) {
	u := strings.TrimSuffix(base, "/") + "/domain/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return domainRecord{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "PhishDetector/1.0 (domain age check)")

	resp, err := rdapClient.Do(req)
	if err != nil {
		return domainRecord{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return domainRecord{Status: DomainNotFound, Source: "rdap"}, nil
	case http.StatusTooManyRequests, http.StatusForbidden:
		return domainRecord{Status: DomainLimited, Source: "rdap", Detail: resp.Status}, nil
	default:
		return domainRecord{}, fmt.Errorf("rdap: %s", resp.Status)
	}

	var doc rdapDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return domainRecord{}, err
	}

	rec := domainRecord{Status: DomainOK, Source: "rdap", Statuses: doc.Status}
	for _, ev := range doc.Events {
		t := parseWhoisDate(ev.EventDate)
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			rec.Created = t
		case "expiration":
			rec.Expires = t
		}
	}
	for _, ent := range doc.Entities {
		for _, role := range ent.Roles {
			if strings.EqualFold(role, "registrar") && rec.Registrar == "" {
				rec.Registrar = vcardFn(ent.VCardArray)
			}
		}
	}
	if rec.Created.IsZero() {
		return domainRecord{}, errors.New("rdap: нет события registration")
	}
	return rec, nil
}

func vcardFn(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		entry, ok := p.([]any)
		if !ok || len(entry) < 4 {
			continue
		}
		if name, _ := entry[0].(string); strings.EqualFold(name, "fn") {
			s, _ := entry[3].(string)
			return s
		}
	}
	return ""
}

func rdapBaseFor(tld string) string {
	rdapMu.RLock()
	defer rdapMu.RUnlock()
	return rdapBase[tld]
}

func rdapCount() int {
	rdapMu.RLock()
	defer rdapMu.RUnlock()
	return len(rdapBase)
}

func initRDAPBootstrap() {
	if info, err := os.Stat(rdapCacheFile); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
		if data, err := os.ReadFile(rdapCacheFile); err == nil && loadRDAPBootstrap(data) == nil {
			log.Printf("RDAP bootstrap: %d TLD из локального кэша", rdapCount())
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBootstrapURL, nil)
	if err != nil {
		return
	}
	resp, err := rdapClient.Do(req)
	if err != nil {
		log.Printf("RDAP bootstrap недоступен (%v); работаем через WHOIS", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("RDAP bootstrap: статус %d", resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		log.Printf("RDAP bootstrap: чтение: %v", err)
		return
	}
	if err := loadRDAPBootstrap(data); err != nil {
		log.Printf("RDAP bootstrap: разбор: %v", err)
		return
	}
	_ = os.WriteFile(rdapCacheFile, data, 0o644)
	log.Printf("RDAP bootstrap загружен: %d TLD", rdapCount())
}

func loadRDAPBootstrap(data []byte) error {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Services) == 0 {
		return errors.New("пустой список services")
	}
	m := make(map[string]string, 1500)
	for _, svc := range doc.Services {
		if len(svc) < 2 {
			continue
		}
		var base string
		for _, u := range svc[1] {
			if strings.HasPrefix(u, "https://") { // только HTTPS
				base = u
				break
			}
		}
		if base == "" {
			continue
		}
		for _, tld := range svc[0] {
			m[strings.ToLower(strings.TrimPrefix(tld, "."))] = base
		}
	}
	rdapMu.Lock()
	rdapBase = m
	rdapMu.Unlock()
	return nil
}

// ---------- WHOIS (порт 43) ----------

func probeWHOIS(ctx context.Context, domain string) (domainRecord, error) {
	tld := domain[strings.LastIndex(domain, ".")+1:]
	server := whoisServers[tld]

	if server == "" {
		text, err := whoisQuery(ctx, "whois.iana.org", tld)
		if err != nil {
			return domainRecord{}, fmt.Errorf("iana: %w", err)
		}
		if rec := parseWhoisText(text, "whois:iana"); rec.Status == DomainLimited {
			return rec, nil
		}
		server = referralServer(text)
		if server == "" {
			return domainRecord{Status: DomainUnknown, Source: "whois:iana",
				Detail: "IANA не указала whois-сервер для ." + tld}, nil
		}
	}

	query := domain
	if strings.Contains(server, "verisign-grs") {
		query = "=" + domain // точное совпадение, иначе Verisign отдаёт список похожих
	}
	text, err := whoisQuery(ctx, server, query)
	if err != nil {
		return domainRecord{}, fmt.Errorf("%s: %w", server, err)
	}
	rec := parseWhoisText(text, "whois:"+server)

	// Реестр не отдал дату — идём к регистратору (максимум один дополнительный хоп).
	if rec.Status == DomainUnknown {
		if ref := referralServer(text); ref != "" && ref != server {
			if t2, err2 := whoisQuery(ctx, ref, domain); err2 == nil {
				if r2 := parseWhoisText(t2, "whois:"+ref); r2.Status == DomainOK {
					if r2.Registrar == "" {
						r2.Registrar = rec.Registrar
					}
					return r2, nil
				}
			}
		}
	}
	return rec, nil
}

func throttleWhois(ctx context.Context, server string) error {
	whoisMu.Lock()
	wait := whoisMinGap - time.Since(whoisLast[server])
	if wait < 0 {
		wait = 0
	}
	whoisLast[server] = time.Now().Add(wait) // резервируем слот
	whoisMu.Unlock()

	if wait == 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func whoisQuery(ctx context.Context, server, query string) (string, error) {
	if !validDomain(server) && net.ParseIP(server) == nil {
		return "", fmt.Errorf("недопустимое имя whois-сервера: %q", server)
	}
	if strings.ContainsAny(query, "\r\n\x00 ") {
		return "", errors.New("недопустимый whois-запрос")
	}
	if err := throttleWhois(ctx, server); err != nil {
		return "", err
	}

	hopCtx, cancel := context.WithTimeout(ctx, whoisHopTimeout)
	defer cancel()

	conn, err := dialPublicTCP(hopCtx, server, "43")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if dl, ok := hopCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil && len(body) == 0 {
		return "", err
	}
	return string(body), nil
}

var (
	createdKeys = map[string]bool{
		"created": true, "creation date": true, "created on": true, "created date": true,
		"registered": true, "registered on": true, "registration date": true,
		"domain registration date": true, "registration time": true, "registered date": true,
		"creation time": true, "domain create date": true, "created date utc": true,
	}
	expiryKeys = map[string]bool{
		"paid-till": true, "registry expiry date": true, "expiry date": true, "expires": true,
		"expires on": true, "expiration date": true, "registry expiration date": true,
		"registrar registration expiration date": true, "expire date": true,
		"renewal date": true, "expiration time": true, "valid until": true,
	}
	registrarKeys = map[string]bool{
		"registrar": true, "registrar name": true, "sponsoring registrar": true,
		"registrar organization": true,
	}
	statusKeys   = map[string]bool{"state": true, "domain status": true, "status": true}
	referralKeys = map[string]bool{
		"whois": true, "registrar whois server": true, "whois server": true,
	}

	limitMarkers = []string{
		"rate limit", "limit exceeded", "quota exceeded", "too many requests",
		"try again later", "exceeded your connection limit", "access denied", "too many queries",
	}
	notFoundMarkers = []string{
		"no match for", "no entries found", "no data found", "no object found",
		"domain not found", "not found", "status: free", "status: available",
	}

	whoisDateLayouts = []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05Z", "2006-01-02T15:04:05.0Z", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05", "2006-01-02 15:04:05-07", "2006-01-02 15:04:05 MST",
		"2006-01-02", "2006.01.02", "2006/01/02", "20060102",
		"02-Jan-2006", "02-Jan-2006 15:04:05", "02.01.2006", "02.01.2006 15:04:05",
		"01/02/2006", "2006-Jan-02", "Jan 02 2006",
	}

	spaceRe = regexp.MustCompile(`\s+`)
	parenRe = regexp.MustCompile(`\(.*?\)`)
)

func normalizeKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.Trim(k, "[]")
	k = parenRe.ReplaceAllString(k, "")
	return strings.TrimSpace(spaceRe.ReplaceAllString(k, " "))
}

func parseWhoisDate(v string) time.Time {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, " UTC")
	for _, layout := range whoisDateLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

func normalizeStatus(s string) string {
	if i := strings.Index(s, "http"); i > 0 {
		s = s[:i]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	return strings.ReplaceAll(s, "-", "")
}

func referralServer(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found || !referralKeys[normalizeKey(k)] {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(v))
		host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
		host = strings.Trim(host, "/ ")
		if validDomain(host) {
			return host
		}
	}
	return ""
}

func parseWhoisText(text, source string) domainRecord {
	rec := domainRecord{Source: source}
	low := strings.ToLower(text)
	for _, m := range limitMarkers {
		if strings.Contains(low, m) {
			rec.Status = DomainLimited
			rec.Detail = "реестр ограничил частоту запросов"
			return rec
		}
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">") {
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, val := normalizeKey(k), strings.TrimSpace(v)
		if val == "" {
			continue
		}
		switch {
		case createdKeys[key]:
			if rec.Created.IsZero() {
				rec.Created = parseWhoisDate(val)
			}
		case expiryKeys[key]:
			if rec.Expires.IsZero() {
				rec.Expires = parseWhoisDate(val)
			}
		case registrarKeys[key]:
			if rec.Registrar == "" {
				rec.Registrar = val
			}
		case statusKeys[key]:
			for _, s := range strings.Split(val, ",") {
				if s = strings.TrimSpace(s); s != "" {
					rec.Statuses = append(rec.Statuses, s)
				}
			}
		}
	}

	// Порядок важен: наличие даты регистрации сильнее любых фраз в дисклеймере.
	if !rec.Created.IsZero() {
		rec.Status = DomainOK
		return rec
	}
	for _, m := range notFoundMarkers {
		if strings.Contains(low, m) {
			rec.Status = DomainNotFound
			return rec
		}
	}
	rec.Status = DomainUnknown
	if len(text) > 300 {
		rec.Detail = strings.TrimSpace(text[:300])
	} else {
		rec.Detail = strings.TrimSpace(text)
	}
	return rec
}

// ---------- скоринг ----------

func buildDomainInfo(domain string, rec domainRecord, cached bool) DomainInfo {
	info := DomainInfo{
		Domain: domain, Status: string(rec.Status), Source: rec.Source,
		Registrar: rec.Registrar, RegistryStatus: rec.Statuses,
		Detail: rec.Detail, ElapsedMS: rec.ElapsedMS, Cached: cached,
		Reasons: []string{},
	}

	if !rec.Created.IsZero() {
		info.Created = rec.Created.UTC().Format(time.RFC3339)
		age := time.Since(rec.Created)
		info.AgeDays = int(age.Hours() / 24)
		date := rec.Created.Format("02.01.2006")

		switch {
		case age < 3*24*time.Hour:
			info.Score = 35
			info.Reasons = append(info.Reasons, fmt.Sprintf(
				"Домен зарегистрирован %s — менее 3 суток назад. Классический признак однодневного фишинга.", date))
		case age < 14*24*time.Hour:
			info.Score = 25
			info.Reasons = append(info.Reasons, fmt.Sprintf(
				"Домен зарегистрирован %d дн. назад (%s) — очень молодой домен.", info.AgeDays, date))
		case age < 30*24*time.Hour:
			info.Score = 15
			info.Reasons = append(info.Reasons, fmt.Sprintf(
				"Домен зарегистрирован менее месяца назад (%s).", date))
		case age < 90*24*time.Hour:
			info.Score = 5
			info.Reasons = append(info.Reasons, fmt.Sprintf(
				"Домен зарегистрирован менее 3 месяцев назад (%s).", date))
		case age > 730*24*time.Hour:
			info.Score = whoisOldBonus
			info.Notes = append(info.Notes, fmt.Sprintf(
				"Домену %.1f лет — возраст снижает риск (−10 к оценке).", age.Hours()/24/365))
		default:
			info.Notes = append(info.Notes, fmt.Sprintf("Возраст домена: %d дн. (зарегистрирован %s).", info.AgeDays, date))
		}
	}

	if !rec.Expires.IsZero() {
		info.Expires = rec.Expires.UTC().Format(time.RFC3339)
		if left := time.Until(rec.Expires); left > 0 && left < 7*24*time.Hour {
			info.Notes = append(info.Notes, "Регистрация домена истекает менее чем через 7 дней.")
		}
	}

	var hold, deleting bool
	for _, s := range rec.Statuses {
		switch normalizeStatus(s) {
		case "serverhold", "clienthold":
			hold = true
		case "pendingdelete", "redemptionperiod":
			deleting = true
		}
	}
	if hold {
		info.Score += 15
		info.Reasons = append(info.Reasons, "Домен снят с делегирования (serverHold/clientHold) — частое следствие жалоб на абьюз или неоплаты.")
	}
	if deleting {
		info.Score += 10
		info.Reasons = append(info.Reasons, "Домен в процессе удаления (pendingDelete/redemptionPeriod).")
	}

	switch rec.Status {
	case DomainNotFound:
		info.Score += 15
		info.Reasons = append(info.Reasons, "Домен не зарегистрирован или уже удалён — ссылка нерабочая.")
	case DomainLimited:
		info.Notes = append(info.Notes, "WHOIS-сервер ограничил частоту запросов. Возраст домена неизвестен, оценка не изменена.")
	case DomainUnknown:
		info.Notes = append(info.Notes, "Дату регистрации определить не удалось — оценка не изменена.")
	case DomainSkipped:
		info.Notes = append(info.Notes, "Проверка домена пропущена.")
	}

	if info.Score > whoisMaxScore {
		info.Score = whoisMaxScore
	}
	return info
}
