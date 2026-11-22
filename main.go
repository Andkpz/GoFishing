package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type CheckRequest struct {
	URL string `json:"url"`
}

type RedirectReport struct {
	Checked      bool     `json:"checked"`
	FinalURL     string   `json:"final_url,omitempty"`
	Chain        []string `json:"chain,omitempty"`
	Count        int      `json:"count"`
	ExternalHost bool     `json:"external_host,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type CheckResult struct {
	URL         string             `json:"url"`
	IsPhish     bool               `json:"is_phish"`
	Score       int                `json:"score"`
	Reasons     []string           `json:"reasons"`
	Domain      string             `json:"domain,omitempty"`
	SSLStatus   string             `json:"ssl_status,omitempty"`
	SSL         *SSLReport         `json:"ssl,omitempty"`
	WhoisStatus string             `json:"whois_status,omitempty"`
	ThreatIntel *ThreatIntelReport `json:"threat_intel,omitempty"`
	Redirects   *RedirectReport    `json:"redirects,omitempty"`
}

var (
	numericHostRegex = regexp.MustCompile(`^[0-9.]+$`)
	suspiciousTLDs   = []string{".xyz", ".top", ".tk", ".ml", ".gq", ".cf", ".ga", ".zip", ".mov", ".icu"}

	urlShorteners = map[string]bool{
		"bit.ly": true, "tinyurl.com": true, "clck.ru": true, "t.co": true,
		"goo.gl": true, "is.gd": true, "vk.cc": true, "cutt.ly": true, "ow.ly": true,
	}

	untrustedPlatforms = map[string]bool{
		"blogspot.com": true,
	}

	protectedBrands = map[string]string{
		"google": "Google", "youtube": "YouTube", "facebook": "Facebook",
		"amazon": "Amazon", "instagram": "Instagram", "linkedin": "LinkedIn",
		"netflix": "Netflix", "microsoft": "Microsoft", "apple": "Apple",
		"github": "GitHub", "paypal": "PayPal", "telegram": "Telegram",
		"whatsapp": "WhatsApp", "yandex": "Яндекс", "sberbank": "Сбербанк",
		"sber": "Сбер", "tbank": "Т-Банк", "tinkoff": "Тинькофф", "vtb": "ВТБ",
		"alfabank": "Альфа-Банк", "gazprombank": "Газпромбанк", "gosuslugi": "Госуслуги",
		"nalog": "ФНС России", "wildberries": "Wildberries", "ozon": "Ozon",
		"avito": "Авито", "mail": "Mail.ru",
	}

	cruxMirrors = []string{
		"https://github.com/zakird/crux-top-lists/raw/main/data/country/ru/202104.csv.gz",
		"https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/country/ru/202104.csv.gz",
	}

	// ОПТИМИЗАЦИЯ: Используем atomic pointer для lock-free чтения белого списка
	trustedDomainsPtr atomic.Value // хранит *map[string]bool

	compiledBrands []struct {
		name     string
		skeleton string
		length   int
	}

	redirectTransport = &http.Transport{
		Proxy:                 nil,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   500 * time.Millisecond,
		ResponseHeaderTimeout: 500 * time.Millisecond,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			return dialPublicTCP(dialCtx, host, port)
		},
	}

	// Кэш результатов проверки
	resultCache     = make(map[string]CheckResult)
	cacheMutex      sync.RWMutex
	cacheExpiration = 10 * time.Minute
)

const (
	cacheFile         = "trusted_domains_cache.txt"
	topDomainsLimit   = 50000
	phishingThreshold = 60
)

func initTrustedDomains() {
	fallback := []string{
		"google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
		"twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
		"netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
		"yandex.ru", "vk.com", "mail.ru", "sberbank.ru", "tbank.ru", "gosuslugi.ru",
	}

	initialMap := make(map[string]bool)
	for _, d := range fallback {
		initialMap[d] = true
	}
	trustedDomainsPtr.Store(&initialMap)

	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
		if loadDomainsFromFile(cacheFile) == nil {
			log.Printf("Загружено доменов из локального кэша")
			return
		}
	}
	go func() {
		log.Println("Загрузка мирового рейтинга доменов (Google CrUX)...")
		if err := downloadAndCacheDomains(); err != nil {
			log.Printf("Не удалось обновить мировой список доменов: %v", err)
			return
		}
		log.Printf("Успешно загружен новый белый список")
	}()
}

func initProtectedBrands() {
	compiledBrands = make([]struct {
		name     string
		skeleton string
		length   int
	}, 0, len(protectedBrands))

	for key := range protectedBrands {
		compiledBrands = append(compiledBrands, struct {
			name     string
			skeleton string
			length   int
		}{
			name:     key,
			skeleton: confusableSkeleton(key),
			length:   len([]rune(key)),
		})
	}
	sort.Slice(compiledBrands, func(i, j int) bool {
		return compiledBrands[i].name < compiledBrands[j].name
	})
}

func downloadAndCacheDomains() error {
	var lastErr error
	for _, mirrorURL := range cruxMirrors {
		if err := fetchFromURL(mirrorURL); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func fetchFromURL(targetURL string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("слишком много редиректов")
			}
			if req.URL.Scheme != "https" || (req.URL.Hostname() != "github.com" && req.URL.Hostname() != "raw.githubusercontent.com") {
				return fmt.Errorf("запрещённый адрес редиректа")
			}
			return nil
		},
	}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "PhishDetector/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул статус %d", resp.StatusCode)
	}

	gzReader, err := gzip.NewReader(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("ошибка распаковки GZIP: %w", err)
	}
	defer gzReader.Close()

	reader := csv.NewReader(io.LimitReader(gzReader, 256<<20))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("не удалось прочитать CSV-заголовок: %w", err)
	}

	originColumn := -1
	for i, field := range header {
		if strings.EqualFold(strings.TrimSpace(field), "origin") {
			originColumn = i
			break
		}
	}
	if originColumn < 0 {
		return fmt.Errorf("в CSV отсутствует колонка origin")
	}

	newMap := make(map[string]bool, topDomainsLimit)
	linesToCache := make([]string, 0, topDomainsLimit)

	for len(linesToCache) < topDomainsLimit {
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("ошибка чтения CSV: %w", readErr)
		}
		if originColumn >= len(record) {
			continue
		}
		rawOrigin := strings.TrimSpace(record[originColumn])
		parsed, parseErr := url.Parse(rawOrigin)
		if parseErr != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" {
			continue
		}
		host, normErr := normalizeHost(parsed.Hostname())
		if normErr != nil || net.ParseIP(host) != nil {
			continue
		}
		rootDomain := getRootDomain(host)
		if rootDomain != "" && !urlShorteners[rootDomain] && !newMap[rootDomain] {
			newMap[rootDomain] = true
			linesToCache = append(linesToCache, rootDomain)
		}
	}

	if len(newMap) == 0 {
		return fmt.Errorf("в ответе %s не найдено ни одного домена", targetURL)
	}

	if err := writeDomainsAtomically(cacheFile, linesToCache); err != nil {
		return fmt.Errorf("не удалось сохранить кэш доменов: %w", err)
	}

	// Атомарная замена указателя на мапу (Lock-Free для читателей)
	trustedDomainsPtr.Store(&newMap)

	return nil
}

func writeDomainsAtomically(filename string, domains []string) error {
	dir := filepath.Dir(filename)
	if dir == "." {
		dir = "."
	}
	f, err := os.CreateTemp(dir, ".trusted-domains-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()

	if _, err = f.WriteString(strings.Join(domains, "\n") + "\n"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filename); err != nil {
		return err
	}
	ok = true
	return nil
}

func loadDomainsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	tempMap := make(map[string]bool)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !urlShorteners[domain] {
			tempMap[domain] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Обновляем глобальный указатель
	trustedDomainsPtr.Store(&tempMap)
	return nil
}

func isTrustedDomain(domain string) bool {
	// Lock-free чтение: получаем текущую версию мапы
	ptr := trustedDomainsPtr.Load().(*map[string]bool)
	return (*ptr)[domain]
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}
	var entropy float64
	length := float64(len([]rune(s)))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(host)), ".")
	if host == "" {
		return "", fmt.Errorf("пустое имя хоста")
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("некорректное IDN-имя: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(ascii) > 253 {
		return "", fmt.Errorf("имя хоста длиннее 253 байт")
	}
	return ascii, nil
}

func getRootDomain(host string) string {
	host, err := normalizeHost(host)
	if err != nil {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return root
}

func levenshteinDistance(a, b string) int {
	r1, r2 := []rune(a), []rune(b)
	n, m := len(r1), len(r2)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	prev := make([]int, m+1)
	curr := make([]int, m+1)
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		curr[0] = i
		for j := 1; j <= m; j++ {
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			minVal := del
			if ins < minVal {
				minVal = ins
			}
			if sub < minVal {
				minVal = sub
			}
			curr[j] = minVal
		}
		prev, curr = curr, prev
	}
	return prev[m]
}

var confusableASCII = map[rune]rune{
	'а': 'a', 'А': 'a', 'ɑ': 'a', 'α': 'a', 'Α': 'a',
	'в': 'b', 'Β': 'b', 'β': 'b',
	'с': 'c', 'С': 'c', 'ϲ': 'c',
	'ԁ': 'd', 'ժ': 'd',
	'е': 'e', 'Е': 'e', 'ε': 'e', 'Ε': 'e',
	'ғ': 'f', 'Ϝ': 'f',
	'ɡ': 'g', 'ց': 'g',
	'һ': 'h', 'Н': 'h', 'Η': 'h',
	'і': 'i', 'І': 'i', 'ι': 'i', 'Ι': 'i', 'ӏ': 'i',
	'ј': 'j', 'ϳ': 'j',
	'κ': 'k', 'Κ': 'k', 'к': 'k', 'К': 'k',
	'ⅼ': 'l',
	'м': 'm', 'М': 'm', 'Μ': 'm',
	'ո': 'n', 'п': 'n', 'Ν': 'n',
	'о': 'o', 'О': 'o', 'ο': 'o', 'Ο': 'o', 'օ': 'o',
	'р': 'p', 'Р': 'p', 'ρ': 'p', 'Ρ': 'p',
	'զ': 'q',
	'г': 'r', 'Γ': 'r',
	'ѕ': 's', 'Ѕ': 's',
	'т': 't', 'Т': 't', 'τ': 't', 'Τ': 't',
	'υ': 'u', 'ս': 'u',
	'ν': 'v', 'ѵ': 'v', 'Ⅴ': 'v',
	'ԝ': 'w', 'ω': 'w', 'ώ': 'w',
	'х': 'x', 'Х': 'x', 'χ': 'x', 'Χ': 'x',
	'у': 'y', 'У': 'y', 'γ': 'y',
	'ᴢ': 'z', 'Ζ': 'z',
}

func confusableSkeleton(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if mapped, ok := confusableASCII[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func scriptFlags(value string) (latin, cyrillic, greek bool) {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			latin = true
		case r >= 0x0400 && r <= 0x052F:
			cyrillic = true
		case r >= 0x0370 && r <= 0x03FF:
			greek = true
		}
	}
	return
}

func damerauLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	n, m := len(ra), len(rb)
	d := make([][]int, n+1)
	for i := range d {
		d[i] = make([]int, m+1)
		d[i][0] = i
	}
	for j := 0; j <= m; j++ {
		d[0][j] = j
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			d[i][j] = minInt(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] && d[i][j] > d[i-2][j-2]+1 {
				d[i][j] = d[i-2][j-2] + 1
			}
		}
	}
	return d[n][m]
}

func minInt(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func checkTyposquatting(domainLabel string) (int, string) {
	label := strings.Trim(domainLabel, "-")
	if len([]rune(label)) < 3 {
		return 0, ""
	}
	latin, cyrillic, greek := scriptFlags(label)
	skeleton := confusableSkeleton(label)

	bestDist, bestBrand := math.MaxInt, ""
	bestHomoglyph := false

	for _, brand := range compiledBrands {
		if label == brand.name {
			continue
		}
		if skeleton == brand.skeleton {
			bestDist, bestBrand, bestHomoglyph = 0, brand.name, true
			break
		}
		dist := damerauLevenshtein(skeleton, brand.name)
		maxDist := 1
		if brand.length >= 7 {
			maxDist = 2
		}
		labelLen := len([]rune(label))
		if dist > 0 && dist <= maxDist && dist < bestDist && labelLen >= brand.length-2 && labelLen <= brand.length+2 {
			bestDist, bestBrand, bestHomoglyph = dist, brand.name, false
		}
	}

	if bestBrand != "" {
		if bestHomoglyph {
			return 65, fmt.Sprintf("Обнаружена возможная homoglyph-подмена бренда %s: доменная метка '%s' визуально имитирует название бренда.", protectedBrands[bestBrand], label)
		}
		return 50, fmt.Sprintf("Возможный тайпсквоттинг: домен '%s' похож на бренд %s (расстояние редактирования: %d).", label, protectedBrands[bestBrand], bestDist)
	}
	if (latin && cyrillic) || (latin && greek) || (cyrillic && greek) {
		return 25, fmt.Sprintf("В доменной метке '%s' смешаны разные письменности; это может использоваться для визуальной подмены символов.", label)
	}
	return 0, ""
}

const (
	redirectMaxHops = 5
	redirectMaxBody = 64 << 10
)

func inspectRedirects(ctx context.Context, startURL string) RedirectReport {
	report := RedirectReport{Checked: true, Chain: []string{}}
	start, err := url.Parse(startURL)
	if err != nil {
		report.Error = "Некорректный URL"
		return report
	}
	startHost, normErr := normalizeHost(start.Hostname())
	if normErr != nil {
		report.Error = "Некорректное имя хоста"
		return report
	}
	if port := start.Port(); port != "" {
		start.Host = net.JoinHostPort(startHost, port)
	} else {
		start.Host = startHost
	}

	chain := []string{start.String()}

	client := &http.Client{
		Timeout:   900 * time.Millisecond,
		Transport: redirectTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > redirectMaxHops {
				return fmt.Errorf("превышен лимит редиректов (%d)", redirectMaxHops)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("запрещённая схема редиректа")
			}
			if req.URL.User != nil {
				return fmt.Errorf("userinfo в адресе редиректа")
			}
			chain = append(chain, req.URL.String())
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start.String(), nil)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	req.Header.Set("User-Agent", "PhishDetector/1.0")
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", redirectMaxBody-1))

	resp, err := client.Do(req)
	if err != nil {
		report.Chain = chain
		report.Count = len(chain) - 1
		if len(chain) > 1 {
			report.FinalURL = chain[len(chain)-1]
			if last, parseErr := url.Parse(report.FinalURL); parseErr == nil {
				report.ExternalHost = !strings.EqualFold(startHost, last.Hostname())
			}
			report.Error = err.Error()
		} else {
			report.Error = "Не удалось безопасно получить ответ: " + err.Error()
		}
		return report
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, redirectMaxBody))
	_ = resp.Body.Close()

	report.Chain = chain
	report.Count = len(chain) - 1
	if resp.Request != nil && resp.Request.URL != nil {
		report.FinalURL = resp.Request.URL.String()
		report.ExternalHost = !strings.EqualFold(startHost, resp.Request.URL.Hostname())
	}
	return report
}

func analyzeURL(ctx context.Context, rawURL string) CheckResult {
	cleanURL := strings.TrimSpace(rawURL)

	// Проверка кэша
	cacheMutex.RLock()
	if cached, found := resultCache[cleanURL]; found {
		cacheMutex.RUnlock()
		return cached
	}
	cacheMutex.RUnlock()

	res := CheckResult{
		URL:     cleanURL,
		Reasons: []string{},
	}
	if cleanURL == "" {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Пустой URL-адрес.")
		return res
	}

	hasExplicitScheme := strings.Contains(cleanURL, "://")
	urlToParse := cleanURL
	if !hasExplicitScheme {
		urlToParse = "https://" + cleanURL
	}

	parsed, err := url.Parse(urlToParse)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Некорректный формат ссылки или маскировка через userinfo.")
		return res
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Разрешены только схемы http и https.")
		return res
	}

	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Некорректное доменное имя: "+err.Error())
		return res
	}
	if port := parsed.Port(); port != "" {
		portNum, convErr := strconv.Atoi(port)
		if convErr != nil || portNum < 1 || portNum > 65535 {
			res.IsPhish = true
			res.Score = 100
			res.Reasons = append(res.Reasons, "Некорректный порт в URL.")
			return res
		}
	}

	rootDomain := getRootDomain(host)
	isIP := net.ParseIP(host) != nil || numericHostRegex.MatchString(host)

	// Ранний возврат для доверенных доменов
	trusted := !isIP && !untrustedPlatforms[rootDomain] && isTrustedDomain(rootDomain)
	if trusted {
		res.Domain = rootDomain
		res.IsPhish = false
		res.Score = 0
		res.Reasons = append(res.Reasons, fmt.Sprintf("Домен '%s' присутствует в рейтинге популярных сайтов и автоматически считается безопасным.", rootDomain))

		// Сохраняем в кэш
		cacheMutex.Lock()
		resultCache[cleanURL] = res
		cacheMutex.Unlock()

		return res
	}

	intel := checkThreatIntel(ctx, urlToParse)
	res.ThreatIntel = &intel
	if intel.Status == "hit" {
		res.Score = 100
		res.IsPhish = true
		res.Reasons = append(res.Reasons, intel.Reasons...)
		return res
	}
	if len(intel.Reasons) > 0 {
		res.Reasons = append(res.Reasons, intel.Reasons...)
	}

	res.Domain = rootDomain
	if !isIP && !urlShorteners[rootDomain] && validDomain(rootDomain) {
		res.WhoisStatus = "pending"
	}

	authority := parsed.Host
	decodedAuthority, decodeErr := url.QueryUnescape(authority)
	hasAtTrick := strings.Contains(authority, "%40") || (decodeErr == nil && strings.Contains(decodedAuthority, "@"))

	unicodeRoot, unicodeErr := idna.ToUnicode(rootDomain)
	if unicodeErr != nil {
		unicodeRoot = rootDomain
	}
	domainLabel, _, _ := strings.Cut(unicodeRoot, ".")

	if !isIP && !urlShorteners[rootDomain] {
		if typoScore, typoReason := checkTyposquatting(domainLabel); typoScore > 0 {
			res.Score += typoScore
			res.Reasons = append(res.Reasons, typoReason)
		}
	}

	if urlShorteners[rootDomain] {
		res.Score += 30
		res.Reasons = append(res.Reasons, fmt.Sprintf("Используется сервис сокращения ссылок (%s), скрывающий конечный адрес.", rootDomain))
	}

	if hasExplicitScheme && parsed.Scheme == "http" {
		res.Score += 15
		res.Reasons = append(res.Reasons, "Используется незащищенный протокол HTTP.")
	}

	if isIP {
		res.Score += 45
		res.Reasons = append(res.Reasons, "Вместо доменного имени используется IP-адрес или числовой формат.")
	}

	if strings.Contains(host, "xn--") {
		res.Score += 35
		res.Reasons = append(res.Reasons, "Обнаружен Punycode (возможна подмена букв на похожие символы).")
	}

	if hasAtTrick {
		res.Score += 45
		res.Reasons = append(res.Reasons, "Ссылка содержит символ '@' (или '%40') до параметров, маскирующий реальный адрес.")
	}

	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(host, tld) {
			res.Score += 25
			res.Reasons = append(res.Reasons, fmt.Sprintf("Используется доменная зона повышенного риска (%s).", tld))
			break
		}
	}

	if len(cleanURL) > 75 {
		res.Score += 15
		res.Reasons = append(res.Reasons, "Подозрительно длинный URL-адрес (более 75 символов).")
	}

	if strings.Count(host, "-") >= 3 {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Чрезмерное количество дефисов в доменном имени.")
	}

	if len(domainLabel) > 10 && calculateEntropy(domainLabel) > 3.8 {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Высокая энтропия домена (имя похоже на случайно сгенерированный набор символов).")
	}

	extraSubdomains := strings.TrimSuffix(host, "."+rootDomain)
	if extraSubdomains != "" {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Подозрительно большое количество поддоменов.")
	}

	keywords := []string{"login", "verify", "update", "secure", "account", "bank", "free"}
	keywordScore := 0
	for _, kw := range keywords {
		if strings.Contains(host, kw) {
			keywordScore += 15
			res.Reasons = append(res.Reasons, fmt.Sprintf("В домене найдено ключевое слово '%s'.", kw))
		}
	}
	if keywordScore > 30 {
		keywordScore = 30
	}
	res.Score += keywordScore

	redirectCtx, redirectCancel := context.WithTimeout(ctx, 900*time.Millisecond)
	redirectReport := inspectRedirects(redirectCtx, urlToParse)
	redirectCancel()
	res.Redirects = &redirectReport

	if redirectReport.Count >= 2 {
		res.Score += 20
		res.Reasons = append(res.Reasons, fmt.Sprintf("Обнаружена цепочка из %d HTTP-редиректов; длинные цепочки могут скрывать конечный адрес.", redirectReport.Count))
	} else if redirectReport.Count == 1 && redirectReport.ExternalHost {
		res.Score += 10
		res.Reasons = append(res.Reasons, "URL перенаправляет на другой домен; проверьте конечный адрес.")
	}
	if redirectReport.Error != "" && len(redirectReport.Chain) > 1 {
		res.Reasons = append(res.Reasons, "Не удалось полностью проверить цепочку редиректов: "+redirectReport.Error)
	}

	if !isIP && !urlShorteners[rootDomain] && res.Score < phishingThreshold {
		rep := checkSSL(ctx, host)
		res.SSL = &rep
		res.SSLStatus = string(rep.Status)
		res.Score += rep.Score
		res.Reasons = append(res.Reasons, rep.Reasons...)
	}

	res.IsPhish = res.Score >= phishingThreshold
	if res.Score > 100 {
		res.Score = 100
	}

	// Сохраняем в кэш
	cacheMutex.Lock()
	resultCache[cleanURL] = res
	cacheMutex.Unlock()

	return res
}

func apiCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)

	var req CheckRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Некорректный JSON", http.StatusBadRequest)
		return
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		http.Error(w, "В теле должен быть ровно один JSON-объект", http.StatusBadRequest)
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		http.Error(w, "Поле url не может быть пустым", http.StatusBadRequest)
		return
	}
	if len(targetURL) > 2048 {
		http.Error(w, "Слишком длинный URL", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	result := analyzeURL(ctx, targetURL)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("encode check: %v", err)
	}
}

func apiDomainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	d := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	d = strings.TrimPrefix(d, "www.")
	if !validDomain(d) {
		http.Error(w, "Некорректный домен", http.StatusBadRequest)
		return
	}
	d = getRootDomain(d)

	ctx, cancel := context.WithTimeout(r.Context(), whoisBudget+time.Second)
	defer cancel()

	info := checkDomain(ctx, d)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("encode domain: %v", err)
	}
}

func main() {
	initTrustedDomains()
	initProtectedBrands()
	initThreatIntel()
	go initRDAPBootstrap()

	tmpl := template.Must(template.ParseFiles(filepath.Join("templates", "index.html")))
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("template: %v", err)
		}
	})

	mux.HandleFunc("/api/check", apiCheckHandler)
	mux.HandleFunc("/api/domain", apiDomainHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	log.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}
