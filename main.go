package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// CheckRequest описывает входящий JSON от клиента
type CheckRequest struct {
	URL string `json:"url"`
}

// CheckResult описывает ответ сервера в формате JSON
type CheckResult struct {
	URL     string   `json:"url"`
	IsPhish bool     `json:"is_phish"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
}

// Выносим регулярное выражение на уровень пакета, чтобы не компилировать его при каждом запросе
var numericHostRegex = regexp.MustCompile(`^[0-9.]+$`)

// Список популярных составных доменных зон
var multiPartTLDs = []string{".co.uk", ".org.uk", ".gov.uk", ".com.au", ".net.au", ".org.ru", ".net.ru", ".com.ru"}

func analyzeURL(rawURL string) CheckResult {
	res := CheckResult{
		URL:     rawURL,
		Reasons: []string{},
	}

	// 1. Проверяем, указал ли пользователь протокол явно
	hasExplicitScheme := strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
	urlToParse := rawURL
	if !hasExplicitScheme {
		urlToParse = "http://" + rawURL
	}

	parsed, err := url.Parse(urlToParse)
	if err != nil || parsed.Host == "" {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Некорректный формат ссылки.")
		return res
	}

	host := strings.ToLower(parsed.Hostname())

	// Штрафуем за HTTP только если пользователь явно ввел http://
	if hasExplicitScheme && parsed.Scheme == "http" {
		res.Score += 15
		res.Reasons = append(res.Reasons, "Используется незащищенный протокол HTTP.")
	}

	// Проверка на IP-адрес (поддерживает и IPv4, и IPv6)
	if net.ParseIP(host) != nil || numericHostRegex.MatchString(host) {
		res.Score += 45
		res.Reasons = append(res.Reasons, "Вместо доменного имени используется IP-адрес или числовой формат.")
	}

	// Проверка на Punycode (IDN-атаки с подменой символов)
	if strings.Contains(host, "xn--") {
		res.Score += 35
		res.Reasons = append(res.Reasons, "Обнаружен Punycode (возможна подмена букв на похожие символы).")
	}

	// 2. Проверяем наличие логина/пароля (символа '@') только в части Userinfo, а не во всей ссылке
	if parsed.User != nil {
		res.Score += 45
		res.Reasons = append(res.Reasons, "Ссылка содержит учетные данные перед символом '@', что часто используется для маскировки реального домена.")
	}

	// 3. Корректный подсчет поддоменов с учетом составных доменных зон
	cleanHost := strings.TrimPrefix(host, "www.")
	effectiveHost := cleanHost
	for _, tld := range multiPartTLDs {
		if strings.HasSuffix(cleanHost, tld) {
			// Заменяем составную зону на условный одноуровневый домен для точного подсчета
			effectiveHost = strings.TrimSuffix(cleanHost, tld) + ".tld"
			break
		}
	}

	parts := strings.Split(effectiveHost, ".")
	// Если частей больше 3 (например, ://domain.com), значит поддоменов 2 и более
	if len(parts) > 3 {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Подозрительно большое количество поддоменов.")
	}

	// Проверка ключевых слов (ограничиваем максимальный штраф за слова, чтобы избежать перекоса)
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

	// 4. Повышенный порог срабатывания (60 баллов вместо 40) для снижения ложных срабатываний
	if res.Score >= 60 {
		res.IsPhish = true
	}
	if res.Score > 100 {
		res.Score = 100
	}

	return res
}

// indexHandler отдает статическую HTML-страницу
func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmplPath := filepath.Join("templates", "index.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// apiCheckHandler принимает JSON и возвращает результат в JSON
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
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/api/check", apiCheckHandler)

	fmt.Println("Сервер запущен на http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
