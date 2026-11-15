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
	"strings"
	"regexp"
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

func analyzeURL(rawURL string) CheckResult {
	res := CheckResult{
		URL:     rawURL,
		Reasons: []string{}, // Инициализируем пустой срез, чтобы в JSON был [], а не null
	}

	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		res.IsPhish = true
		res.Score = 100
		res.Reasons = append(res.Reasons, "Некорректный формат ссылки.")
		return res
	}

	host := parsed.Hostname()

	if parsed.Scheme != "https" {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Отсутствует шифрование HTTPS.")
	}

	isNumericHost, _ := regexp.MatchString(`^[0-9.]+$`, host)
	if net.ParseIP(host) != nil || isNumericHost {
		res.Score += 40
		res.Reasons = append(res.Reasons, "Вместо доменного имени используется IP-адрес или числовой формат.")
	}

	if strings.Contains(host, "xn--") {
		res.Score += 35
		res.Reasons = append(res.Reasons, "Обнаружен Punycode (возможна подмена букв на похожие символы).")
	}

	if strings.Contains(rawURL, "@") {
		res.Score += 40
		res.Reasons = append(res.Reasons, "Ссылка содержит символ '@', который может скрывать реальный домен.")
	}

	parts := strings.Split(host, ".")
	if len(parts) > 3 {
		res.Score += 20
		res.Reasons = append(res.Reasons, "Подозрительно большое количество поддоменов.")
	}

	keywords := []string{"login", "verify", "update", "secure", "account", "bank", "free"}
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(host), kw) {
			res.Score += 15
			res.Reasons = append(res.Reasons, fmt.Sprintf("В домене найдено ключевое слово '%s'.", kw))
		}
	}

	if res.Score >= 40 {
		res.IsPhish = true
	}
	if res.Score > 100 {
		res.Score = 100
	}

	return res
}

// indexHandler просто отдает статическую HTML-страницу
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
