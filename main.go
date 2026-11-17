package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CheckRequest struct {
	URL string `json:"url"`
}

type CheckResult struct {
	URL     string   `json:"url"`
	IsPhish bool     `json:"is_phish"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}

type sslCacheEntry struct {
	score     int
	reasons   []string
	checkedAt time.Time
}

var (
	numericHostRegex = regexp.MustCompile(`^[0-9.]+$`)
	multiPartTLDs    = []string{".co.uk", ".org.uk", ".gov.uk", ".com.au", ".net.au", ".org.ru", ".net.ru", ".com.ru"}
	suspiciousTLDs   = []string{".xyz", ".top", ".tk", ".ml", ".gq", ".cf", ".ga", ".zip", ".mov", ".icu"}

	urlShorteners = map[string]bool{
		"bit.ly": true, "tinyurl.com": true, "clck.ru": true, "t.co": true,
		"goo.gl": true, "is.gd": true, "vk.cc": true, "cutt.ly": true, "ow.ly": true,
	}

	protectedBrands = map[string]string{
		"google":      "Google",
		"youtube":     "YouTube",
		"facebook":    "Facebook",
		"amazon":      "Amazon",
		"instagram":   "Instagram",
		"linkedin":    "LinkedIn",
		"netflix":     "Netflix",
		"microsoft":   "Microsoft",
		"apple":       "Apple",
		"github":      "GitHub",
		"paypal":      "PayPal",
		"telegram":    "Telegram",
		"whatsapp":    "WhatsApp",
		"yandex":      "Яндекс",
		"sberbank":    "Сбербанк",
		"sber":        "Сбер",
		"tbank":       "Т-Банк",
		"tinkoff":     "Тинькофф",
		"vtb":         "ВТБ",
		"alfabank":    "Альфа-Банк",
		"gazprombank": "Газпромбанк",
		"gosuslugi":   "Госуслуги",
		"nalog":       "ФНС России",
		"wildberries": "Wildberries",
		"ozon":        "Ozon",
		"avito":       "Авито",
		"mail":        "Mail.ru",
	}

	cruxMirrors = []string{
		"https://github.com",
		"https://github.com",
	}

	trustedDomains = make(map[string]bool)
	domainsMutex   sync.RWMutex

	sslCache      = make(map[string]sslCacheEntry)
	sslCacheMutex sync.RWMutex
)

const (
	cacheFile       = "trusted_domains_cache.txt"
	topDomainsLimit = 50000
	sslCacheTTL     = 10 * time.Minute
)
func initTrustedDomains() {
	fallback := []string{
		"google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
		"twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
		"netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
		"yandex.ru", "vk.com", "mail.ru", "sberbank.ru", "tbank.ru", "gosuslugi.ru",
	}
	domainsMutex.Lock()
	for _, d := range fallback {
		trustedDomains[d] = true
	}
	domainsMutex.Unlock()

	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
		if loadDomainsFromFile(cacheFile) == nil {
			log.Printf("Загружено %d мировых доменов из локального кэша", len(trustedDomains))
			return
		}
	}

	go func() {
		log.Println("Загрузка мирового рейтинга доменов (Google CrUX)...")
		if err := downloadAndCacheDomains(); err != nil {
			log.Printf("Не удалось обновить мировой список доменов (используется базовый): %v", err)
			return
		}
		log.Printf("Успешно загружено %d мировых доменов в белый список", len(trustedDomains))
	}()
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
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishDetector/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("сервер вернул статус %d для %s", resp.StatusCode, targetURL)
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("ошибка распаковки GZIP: %v", err)
	}
	defer gzReader.Close()

	newMap := make(map[string]bool, topDomainsLimit)
	var linesToCache []string

	scanner := bufio.NewScanner(gzReader)
	count := 0
	isHeader := true

	for scanner.Scan() && count < topDomainsLimit {
		line := scanner.Text()
		if isHeader {
			isHeader = false
			continue
		}

		rawOrigin, _, found := strings.Cut(line, ",")
		if !found {
			continue
		}

		parsed, err := url.Parse(strings.TrimSpace(strings.ToLower(rawOrigin)))
		if err != nil || parsed.Hostname() == "" {
			continue
		}

		rootDomain := getRootDomain(parsed.Hostname())
		if rootDomain != "" && !urlShorteners[rootDomain] && !newMap[rootDomain] {
			newMap[rootDomain] = true
			linesToCache = append(linesToCache, rootDomain)
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	domainsMutex.Lock()
	for k, v := range newMap {
		trustedDomains[k] = v
	}
	domainsMutex.Unlock()

	_ = os.WriteFile(cacheFile, []byte(strings.Join(linesToCache, "\n")), 0644)
	return nil
}

func loadDomainsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	domainsMutex.Lock()
	defer domainsMutex.Unlock()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !urlShorteners[domain] {
			trustedDomains[domain] = true
		}
	}
	return scanner.Err()
}

func isTrustedDomain(domain string) bool {
	domainsMutex.RLock()
	defer domainsMutex.RUnlock()
	return trustedDomains[domain]
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

func getRootDomain(host string) string {
	cleanHost := strings.TrimPrefix(host, "www.")
	for _, tld := range multiPartTLDs {
		if strings.HasSuffix(cleanHost, tld) {
			withoutTLD := strings.TrimSuffix(cleanHost, tld)
			parts := strings.Split(withoutTLD, ".")
			return parts[len(parts)-1] + tld
		}
	}
	parts := strings.Split(cleanHost, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return cleanHost
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

func checkTyposquatting(domainLabel string) (int, string) {
	if len(domainLabel) < 3 {
		return 0, ""
	}

	for brandKey, brandName := range protectedBrands {
		if domainLabel == brandKey {
			continue
		}

		maxDist := 1
		if len([]rune(brandKey)) >= 7 {
			maxDist = 2
		}

		dist := levenshteinDistance(domainLabel, brandKey)
		if dist > 0 && dist <= maxDist {
			return 55, fmt.Sprintf("Возможный тайпсквоттинг: домен '%s' подозрительно похож на бренд %s (разница в %d симв.).", domainLabel, brandName, dist)
		}
	}
	return 0, ""
}

func checkSSL(host string) (int, []string) {
	if net.ParseIP(host) != nil {
		return 0, nil
	}

	sslCacheMutex.RLock()
	if cached, exists := sslCache[host]; exists && time.Since(cached.checkedAt) < sslCacheTTL {
		sslCacheMutex.RUnlock()
		return cached.score, cached.reasons
	}
	sslCacheMutex.RUnlock()

	var score int
	var reasons []string

	dialer := &net.Dialer{Timeout: 4 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName: host,
	})

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			score += 30
			reasons = append(reasons, "Таймаут SSL-проверки: сервер слишком долго не отвечает по порту 443.")
		} else {
			score += 65
			reasons = append(reasons, fmt.Sprintf("Ошибка SSL/TLS: %v", err))
		}
	} else {
		defer conn.Close()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			leaf := certs[0]

			if time.Since(leaf.NotBefore) < 7*24*time.Hour {
				score += 25
				reasons = append(reasons, fmt.Sprintf("SSL-сертификат выпущен совсем недавно (%s) — частый признак однодневного фишинга.", leaf.NotBefore.Format("02.01.2006")))
			}

			if time.Until(leaf.NotAfter) < 3*24*time.Hour {
				score += 20
				reasons = append(reasons, "Срок действия SSL-сертификата истекает менее чем через 3 дня.")
			}
		}
	}

	sslCacheMutex.Lock()
	sslCache[host] = sslCacheEntry{
		score:     score,
		reasons:   reasons,
		checkedAt: time.Now(),
	}
	sslCacheMutex.Unlock()

	return score, reasons
}
func analyzeURL(rawURL string) CheckResult {
	cleanURL := strings.TrimSpace(rawURL)
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

	lowerURL := strings.ToLower(cleanURL)
	hasExplicitScheme := strings.HasPrefix(lowerURL, "http://") || strings.HasPrefix(lowerURL, "https://")
	urlToParse := cleanURL
	if !hasExplicitScheme {
		urlToParse = "http://" + cleanURL
	}

	parsed, err := url.Parse(urlToParse)
	if err != nil || parsed.Host == "" {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Некорректный формат ссылки.")
		return res
	}

	host := strings.ToLower(parsed.Hostname())
	rootDomain := getRootDomain(host)
	isIP := net.ParseIP(host) != nil || numericHostRegex.MatchString(host)

	beforeQuery, _, _ := strings.Cut(lowerURL, "?")
	hasAtTrick := parsed.User != nil || strings.Contains(beforeQuery, "@") || strings.Contains(beforeQuery, "%40")

	if !hasAtTrick && !isIP && isTrustedDomain(rootDomain) {
		res.IsPhish = false
		res.Score = 0
		res.Reasons = append(res.Reasons, fmt.Sprintf("Домен '%s' входит в мировой рейтинг доверенных сайтов.", rootDomain))
		return res
	}

	domainLabel, _, _ := strings.Cut(rootDomain, ".")
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

	cleanHost := strings.TrimPrefix(host, "www.")
	effectiveHost := cleanHost
	for _, tld := range multiPartTLDs {
		if strings.HasSuffix(cleanHost, tld) {
			effectiveHost = strings.TrimSuffix(cleanHost, tld) + ".tld"
			break
		}
	}
	if len(strings.Split(effectiveHost, ".")) > 3 {
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

	if !isIP && !urlShorteners[rootDomain] && res.Score < 100 {
		sslScore, sslReasons := checkSSL(host)
		res.Score += sslScore
		res.Reasons = append(res.Reasons, sslReasons...)
	}

	if res.Score >= 60 {
		res.IsPhish = true
	}
	if res.Score > 100 {
		res.Score = 100
	}

	return res
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmplPath := filepath.Join("templates", "index.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func apiCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Некорректный JSON", http.StatusBadRequest)
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		http.Error(w, "Поле url не может быть пустым", http.StatusBadRequest)
		return
	}

	result := analyzeURL(targetURL)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main() {
	initTrustedDomains()

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/api/check", apiCheckHandler)

	fmt.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
