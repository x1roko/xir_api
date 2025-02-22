package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var jwtKey []byte
var db *gorm.DB

type User struct {
	gorm.Model
	Username string `json:"username" gorm:"unique"`
	Password string `json:"password"`
}

// enableCors enables CORS for a specific response
func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

// CORS middleware
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASSWORD") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	db.AutoMigrate(&User{})

	router := mux.NewRouter()
	router.Use(corsMiddleware)
	
	router.HandleFunc("/register", Register).Methods("POST", "OPTIONS")
	router.HandleFunc("/login", Login).Methods("POST", "OPTIONS")
	router.HandleFunc("/refresh-token", RefreshToken).Methods("POST", "OPTIONS")

	log.Println("Auth Service started at 0.0.0.0:8081")
	log.Fatal(http.ListenAndServe("0.0.0.0:8081", router))
}

func Register(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	result := db.Create(&user)
	if result.Error != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "User already exists"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful"})
}

func Login(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	var foundUser User
	result := db.Where("username = ? AND password = ?", user.Username, user.Password).First(&foundUser)
	if result.Error != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(2400 * time.Hour)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Id:        strconv.FormatUint(uint64(foundUser.ID), 10),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tokenString,
		"status": "success",
		"user": map[string]interface{}{
			"id": foundUser.ID,
			"username": foundUser.Username,
		},
	})
}

func RefreshToken(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	w.Header().Set("Content-Type", "application/json")

	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Authorization header not found"})
		return
	}

	tokenStr = tokenStr[len("Bearer "):]
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid token"})
		return
	}

	expirationTime := time.Now().Add(2400 * time.Hour)
	newClaims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		Id:        claims.Id,
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	newTokenString, err := newToken.SignedString(jwtKey)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": newTokenString})
}
