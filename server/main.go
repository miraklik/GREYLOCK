package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	UploadPath  string `json:"upload_path"`
	UseTLS      bool   `json:"use_tls"`
	AuthToken   string `json:"auth_token"`
	MaxFileSize int64  `json:"max_file_size"`
}

type ResultFile struct {
	Filename    string       `json:"filename"`
	Size        int64        `json:"size"`
	UploadTime  time.Time    `json:"upload_time"`
	ClientIP    string       `json:"client_ip"`
	ScanResults []ScanResult `json:"scan_results,omitempty"`
}

type ScanResult struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
	LineNum int    `json:"line_num"`
	Content string `json:"content"`
}

var config Config

func main() {
	loadConfig("config.json")

	if err := os.MkdirAll(config.UploadPath, 0755); err != nil {
		log.Fatalf("Ошибка создания директории: %v", err)
	}

	// Настройка HTTP обработчиков
	http.HandleFunc("/upload", authMiddleware(uploadHandler))
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/results", authMiddleware(resultsHandler))

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)

	log.Printf("Запуск C2 сервера на %s", addr)
	log.Printf("Директория для загрузок: %s", config.UploadPath)
	log.Printf("Использование TLS: %v", config.UseTLS)

	if config.UseTLS {
		if err := http.ListenAndServeTLS(addr, config.TLSCert, config.TLSKey, nil); err != nil {
			log.Fatalf("Ошибка запуска TLS сервера: %v", err)
		}
	} else {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("Ошибка запуска сервера: %v", err)
		}
	}
}

func loadConfig(configFile string) {
	config = Config{
		Host:        "localhost",
		Port:        8080,
		UploadPath:  "./uploads",
		UseTLS:      false,
		AuthToken:   "secret_token_123",
		MaxFileSize: 1000 * 1024 * 1024,
	}

	if data, err := os.ReadFile(configFile); err == nil {
		if err := json.Unmarshal(data, &config); err != nil {
			log.Printf("Ошибка чтения конфигурации: %v", err)
		}
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+config.AuthToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, config.MaxFileSize)

	if err := r.ParseMultipartForm(config.MaxFileSize); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка парсинга формы: %v", err), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("results")
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка получения файла: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("results_%s_%s", timestamp, header.Filename)
	filepath := filepath.Join(config.UploadPath, filename)

	dst, err := os.Create(filepath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка создания файла: %v", err), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	written, err := io.Copy(dst, file)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка сохранения файла: %v", err), http.StatusInternalServerError)
		return
	}
	clientIP := getClientIP(r)

	resultFile := ResultFile{
		Filename:   filename,
		Size:       written,
		UploadTime: time.Now(),
		ClientIP:   clientIP,
	}

	if err := saveResultFile(resultFile); err != nil {
		http.Error(w, fmt.Sprintf("Ошибка сохранения информации о файле: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Получен файл: %s (%.2f KB) от %s", filename, float64(header.Size)/1024, clientIP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":   "success",
		"filename": filename,
		"size":     header.Size,
		"message":  "File uploaded successfully",
	})
}

func saveResultFile(file ResultFile) error {
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "online",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	})
}

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := os.ReadDir(config.UploadPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка чтения директории: %v", err), http.StatusInternalServerError)
		return
	}

	var resultFiles []ResultFile
	for _, file := range files {
		if !file.IsDir() {
			info, err := file.Info()
			if err != nil {
				continue
			}

			resultFiles = append(resultFiles, ResultFile{
				Filename:   file.Name(),
				Size:       info.Size(),
				UploadTime: info.ModTime(),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resultFiles)
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
