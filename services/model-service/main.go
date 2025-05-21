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
	ID          uint      `json:"id" gorm:"primaryKey"`
	Name        string    `json:"name" gorm:"uniqueIndex"`
	Description string    `json:"description"`
	Parameters  string    `json:"parameters"`
	Tags        []string  `json:"tags" gorm:"type:json"`
	OllamaTag   string    `json:"ollama_tag"`
	Pulls       int64     `json:"pulls"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type ModelOperation struct {
	gorm.Model
	UserID    uint      `json:"user_id" gorm:"index"`
	ModelName string    `json:"model_name"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"created_at"`
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
	if err := c.client.Set(ctx, "models", data, time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to set models in cache: %v", err)
	}
	return nil
}

func (c *RedisCache) GetLastSyncTime(ctx context.Context) (time.Time, error) {
	val, err := c.client.Get(ctx, "last_sync").Result()
	if err == redis.Nil {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get last sync time: %v", err)
	}
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse last sync time: %v", err)
	}
	return t, nil
}

func (c *RedisCache) SetLastSyncTime(ctx context.Context, t time.Time) error {
	return c.client.Set(ctx, "last_sync", t.Format(time.RFC3339), 0).Err()
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

func syncModelsToRedis() {
	cacheClient := NewRedisCache(os.Getenv("REDIS_ADDR"), "", 0)
	ctx := context.Background()

	for {
		lastSync, err := cacheClient.GetLastSyncTime(ctx)
		if err != nil {
			log.Printf("Failed to get last sync time: %v", err)
		}

		if lastSync.IsZero() || time.Since(lastSync) >= time.Hour {
			var models []Model
			if err := db.Find(&models).Error; err != nil {
				log.Printf("Failed to fetch models from DB: %v", err)
			} else {
				if err := cacheClient.SetModels(ctx, models); err != nil {
					log.Printf("Failed to cache models: %v", err)
				}
				if err := cacheClient.SetLastSyncTime(ctx, time.Now()); err != nil {
					log.Printf("Failed to set last sync time: %v", err)
				}
				log.Printf("Synced %d models to Redis", len(models))
			}
		}
		time.Sleep(time.Hour)
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

	if err := db.AutoMigrate(&ModelOperation{}, &Model{}); err != nil {
		log.Fatalf("Failed to auto migrate database: %v", err)
	}

	go syncModelsToRedis()

	router := mux.NewRouter()
	router.Use(corsMiddleware)
	router.HandleFunc("/models", GetModels).Methods("GET", "OPTIONS")
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
		if err := db.Find(&models).Error; err != nil {
			log.Printf("Error getting models from DB: %v", err)
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
