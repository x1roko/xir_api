package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Model struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Size        string   `json:"size"`
	Parameters  string   `json:"parameters"`
	Tags        []string `json:"tags"`
	OllamaTag   string   `json:"ollama_tag"`
}

type ModelOperation struct {
	gorm.Model
	UserID    uint      `json:"user_id" gorm:"index"`
	ModelName string    `json:"model_name"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"created_at"`
}

type HFClient struct {
	BaseURL string
	Token   string
}

func NewHFClient(baseURL, token string) *HFClient {
	return &HFClient{BaseURL: baseURL, Token: token}
}

func (c *HFClient) GetModels(filterTags []string, maxSize, minParameters string) ([]Model, error) {
	url := c.BaseURL + "/models?filter=gguf"
	if len(filterTags) > 0 {
		url += "&tags=" + strings.Join(filterTags, ",")
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var hfModels []struct {
		ID          string   `json:"id"`
		Tags        []string `json:"tags"`
		PipelineTag string   `json:"pipeline_tag"`
		CreatedAt   string   `json:"createdAt"`
		Downloads   int      `json:"downloads"`
		Likes       int      `json:"likes"`
		Private     bool     `json:"private"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&hfModels); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	var models []Model
	for _, m := range hfModels {
		if contains(m.Tags, "gguf") {
			// Используем доступные поля из API
			description := fmt.Sprintf("Downloads: %d, Likes: %d, Created: %s",
				m.Downloads, m.Likes, m.CreatedAt)

			// Пытаемся извлечь параметры из тегов
			parameters := extractParametersFromTags(m.Tags)

			models = append(models, Model{
				ID:          m.ID,
				Name:        m.ID,
				Description: description,
				Size:        "N/A", // Размер не доступен в API
				Parameters:  parameters,
				Tags:        m.Tags,
				OllamaTag:   mapToOllamaTag(m.ID),
			})
		}
	}

	return models, nil
}

func extractParametersFromTags(tags []string) string {
	for _, tag := range tags {
		if strings.Contains(tag, "B") && !strings.Contains(tag, "base_model") {
			// Пытаемся найти тег с параметрами модели (например, "7B")
			return tag
		}
	}
	return ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func formatSize(bytes int64) string {
	const (
		GB = 1 << 30
		MB = 1 << 20
		KB = 1 << 10
	)

	if bytes >= GB {
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	}
	if bytes >= MB {
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	}
	if bytes >= KB {
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	}
	return fmt.Sprintf("%d B", bytes)
}

func mapToOllamaTag(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) > 1 {
		name := strings.ToLower(parts[1])
		name = strings.ReplaceAll(name, "llama-", "llama")
		name = strings.ReplaceAll(name, "-gguf", "")
		name = strings.ReplaceAll(name, "_gguf", "")
		name = strings.ReplaceAll(name, ".gguf", "")
		name = strings.ReplaceAll(name, " ", "-")
		return name
	}
	return strings.ToLower(id)
}

func sizeMeetsRequirement(size, maxSize string) bool {
	if size == "N/A" || maxSize == "" {
		return true
	}

	sizeVal, err := parseSize(size)
	if err != nil {
		log.Printf("Invalid size format: %v", err)
		return false
	}

	maxSizeVal, err := parseSize(maxSize)
	if err != nil {
		log.Printf("Invalid max_size format: %v", err)
		return false
	}

	return sizeVal <= maxSizeVal
}

func parametersMeetRequirement(params, minParams string) bool {
	if params == "" || minParams == "" {
		return true
	}

	paramsVal, err := parseParameters(params)
	if err != nil {
		log.Printf("Invalid parameters format: %v", err)
		return false
	}

	minParamsVal, err := parseParameters(minParams)
	if err != nil {
		log.Printf("Invalid min_parameters format: %v", err)
		return false
	}

	return paramsVal >= minParamsVal
}

func parseSize(size string) (float64, error) {
	size = strings.TrimSpace(size)
	if size == "" || size == "N/A" {
		return 0, nil
	}

	var val float64
	if strings.HasSuffix(size, "GB") {
		_, err := fmt.Sscanf(size, "%f GB", &val)
		return val * 1024, err // Convert GB to MB
	}
	if strings.HasSuffix(size, "MB") {
		_, err := fmt.Sscanf(size, "%f MB", &val)
		return val, err
	}
	if strings.HasSuffix(size, "KB") {
		_, err := fmt.Sscanf(size, "%f KB", &val)
		return val / 1024, err // Convert KB to MB
	}
	if strings.HasSuffix(size, "B") {
		_, err := fmt.Sscanf(size, "%f B", &val)
		return val / (1024 * 1024), err // Convert B to MB
	}
	return 0, fmt.Errorf("invalid size format: %s", size)
}

func parseParameters(params string) (float64, error) {
	params = strings.TrimSpace(params)
	if params == "" {
		return 0, nil
	}

	var val float64
	if strings.HasSuffix(params, "B") {
		_, err := fmt.Sscanf(params, "%fB", &val)
		return val, err
	}
	if strings.Contains(params, "B") {
		// Handle cases like "7B" without space
		parts := strings.Split(params, "B")
		if len(parts) > 0 {
			val, err := strconv.ParseFloat(parts[0], 64)
			if err != nil {
				return 0, fmt.Errorf("invalid parameters format: %s", params)
			}
			return val, nil
		}
	}
	return 0, fmt.Errorf("invalid parameters format: %s", params)
}

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr, password string, db int) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})
	return &RedisCache{client: client}
}

func (c *RedisCache) GetModels(ctx context.Context) ([]Model, error) {
	val, err := c.client.Get(ctx, "models").Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get models from cache: %v", err)
	}

	var models []Model
	if err := json.Unmarshal([]byte(val), &models); err != nil {
		return nil, fmt.Errorf("failed to unmarshal models from cache: %v", err)
	}
	return models, nil
}

func (c *RedisCache) SetModels(ctx context.Context, models []Model) error {
	data, err := json.Marshal(models)
	if err != nil {
		return fmt.Errorf("failed to marshal models for cache: %v", err)
	}
	if err := c.client.Set(ctx, "models", data, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to set models in cache: %v", err)
	}
	return nil
}

var (
	jwtKey []byte
	db     *gorm.DB
)

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header not found", http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(jwtKey) == 0 {
		log.Fatal("JWT_SECRET_KEY is not set")
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"), os.Getenv("DB_NAME"))

	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err := db.AutoMigrate(&ModelOperation{}); err != nil {
		log.Fatalf("Failed to auto migrate database: %v", err)
	}

	router := mux.NewRouter()
	router.Use(corsMiddleware)
	router.HandleFunc("/models", GetModels).Methods("GET", "OPTIONS")
	router.HandleFunc("/models/filter", FilterModels).Methods("GET", "OPTIONS")
	router.HandleFunc("/operations", authenticate(GetOperations)).Methods("GET", "OPTIONS")

	log.Println("Model service running on 0.0.0.0:8085")
	log.Fatal(http.ListenAndServe("0.0.0.0:8085", router))
}

func GetModels(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	cacheClient := NewRedisCache(os.Getenv("REDIS_ADDR"), "", 0)
	models, err := cacheClient.GetModels(r.Context())
	if err != nil {
		log.Printf("Error getting models from cache: %v", err)
		http.Error(w, fmt.Sprintf("Error getting models: %v", err), http.StatusInternalServerError)
		return
	}

	if models == nil {
		hfClient := NewHFClient(os.Getenv("HF_API_URL"), os.Getenv("HF_TOKEN"))
		models, err = hfClient.GetModels(nil, "", "")
		if err != nil {
			log.Printf("Error getting models from Hugging Face API: %v", err)
			http.Error(w, fmt.Sprintf("Error getting models: %v", err), http.StatusInternalServerError)
			return
		}

		if err := cacheClient.SetModels(r.Context(), models); err != nil {
			log.Printf("Failed to cache models: %v", err)
		}

		if err := db.Create(&ModelOperation{
			UserID:    0,
			ModelName: "all",
			Operation: "list",
		}).Error; err != nil {
			log.Printf("Failed to create model operation: %v", err)
		}
	}

	if err := json.NewEncoder(w).Encode(models); err != nil {
		log.Printf("Failed to encode models: %v", err)
	}
}

func FilterModels(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	query := r.URL.Query()
	tags := strings.Split(query.Get("tags"), ",")
	if len(tags) == 1 && tags[0] == "" {
		tags = nil
	}
	maxSize := query.Get("max_size")
	minParameters := query.Get("min_parameters")

	cacheClient := NewRedisCache(os.Getenv("REDIS_ADDR"), "", 0)
	cacheKey := fmt.Sprintf("models:%s:%s:%s", strings.Join(tags, ","), maxSize, minParameters)

	val, err := cacheClient.client.Get(r.Context(), cacheKey).Result()
	if err == redis.Nil {
		hfClient := NewHFClient(os.Getenv("HF_API_URL"), os.Getenv("HF_TOKEN"))
		models, err := hfClient.GetModels(tags, maxSize, minParameters)
		if err != nil {
			log.Printf("Error getting filtered models from Hugging Face API: %v", err)
			http.Error(w, fmt.Sprintf("Error getting filtered models: %v", err), http.StatusInternalServerError)
			return
		}

		// Фильтруем модели по параметрам
		var filteredModels []Model
		for _, model := range models {
			if maxSize != "" && !sizeMeetsRequirement(model.Size, maxSize) {
				continue
			}
			if minParameters != "" && !parametersMeetRequirement(model.Parameters, minParameters) {
				continue
			}
			filteredModels = append(filteredModels, model)
		}

		data, err := json.Marshal(filteredModels)
		if err != nil {
			log.Printf("Error marshaling filtered models: %v", err)
			http.Error(w, fmt.Sprintf("Error marshaling filtered models: %v", err), http.StatusInternalServerError)
			return
		}

		if err := cacheClient.client.Set(r.Context(), cacheKey, data, 24*time.Hour).Err(); err != nil {
			log.Printf("Failed to cache filtered models: %v", err)
		}

		if err := json.NewEncoder(w).Encode(filteredModels); err != nil {
			log.Printf("Failed to encode filtered models: %v", err)
		}

		if err := db.Create(&ModelOperation{
			UserID:    0,
			ModelName: "filtered",
			Operation: "filter",
		}).Error; err != nil {
			log.Printf("Failed to create model operation: %v", err)
		}
		return
	}

	if err != nil {
		log.Printf("Error getting filtered models from cache: %v", err)
		http.Error(w, fmt.Sprintf("Error getting filtered models: %v", err), http.StatusInternalServerError)
		return
	}

	var models []Model
	if err := json.Unmarshal([]byte(val), &models); err != nil {
		log.Printf("Error unmarshaling filtered models from cache: %v", err)
		http.Error(w, fmt.Sprintf("Error unmarshaling filtered models: %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(models); err != nil {
		log.Printf("Failed to encode filtered models: %v", err)
	}
}

func GetOperations(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header not found", http.StatusUnauthorized)
		return
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(claims.Id, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var operations []ModelOperation
	if err := db.Where("user_id = ?", userID).Order("created_at asc").Find(&operations).Error; err != nil {
		log.Printf("Failed to get operations: %v", err)
		http.Error(w, fmt.Sprintf("Failed to get operations: %v", err), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(operations); err != nil {
		log.Printf("Failed to encode operations: %v", err)
	}
}
