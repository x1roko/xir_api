package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Переменные для хранения ключа JWT и подключения к базе данных
var jwtKey []byte
var db *gorm.DB

// User представляет модель пользователя в базе данных
type User struct {
	gorm.Model
	Username string `json:"username" gorm:"unique"` // Уникальное имя пользователя
	Password string `json:"password"`               // Пароль пользователя
}

// GroqRequest представляет запрос к API Groq
type GroqRequest struct {
	Text string `json:"text"` // Текст запроса
}

func main() {
	// Загрузка переменных окружения из .env файла
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Инициализация ключа JWT из переменной окружения
	jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

	// Подключение к MySQL
	dsn := os.Getenv("DB_USER") + ":" + os.Getenv("DB_PASSWORD") + "@tcp(" + os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT") + ")/" + os.Getenv("DB_NAME") + "?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// Автоматическая миграция модели User в базе данных
	db.AutoMigrate(&User{})

	// Определение обработчиков HTTP-запросов
	http.HandleFunc("/register", Register)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/groq", Groq)

	// Запуск HTTP-сервера на порту 8080
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Register обрабатывает регистрацию нового пользователя
func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	// Декодирование JSON-данных из тела запроса в структуру User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Создание нового пользователя в базе данных
	result := db.Create(&user)
	if result.Error != nil {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}
	w.Write([]byte("Registration successful"))
}

// Login обрабатывает вход пользователя
func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	// Декодирование JSON-данных из тела запроса в структуру User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var foundUser User
	// Поиск пользователя в базе данных по имени пользователя и паролю
	result := db.Where("username = ? AND password = ?", user.Username, user.Password).First(&foundUser)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Установка времени истечения токена
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
	}
	// Создание нового токена JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка токена в куки
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
}

// CallGroqAPI отправляет запрос к API Groq и возвращает ответ
func CallGroqAPI(text string) (string, error) {
	url := "https://api.groq.com/openai/v1/chat/completions"
	apiKey := os.Getenv("GROQ_API_KEY")

	// Подготовка данных для запроса
	jsonData := map[string]interface{}{
		"model": "llama-3.3-70b-versatile",
		"messages": []map[string]string{

			{
				"role":    "user", // Роль отправителя сообщения
				"content": text,   // Содержимое сообщения
			},
		},
	}

	// Преобразование данных в формат JSON
	jsonValue, _ := json.Marshal(jsonData)
	// Создание нового HTTP-запроса
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}

	// Установка заголовков для запроса
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey) // Установка API ключа в заголовок

	client := &http.Client{}
	// Выполнение запроса
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close() // Закрытие тела ответа после завершения работы с ним

	// Чтение и декодирование ответа
	var result map[string]interface{}
	body, _ := ioutil.ReadAll(response.Body)
	json.Unmarshal(body, &result)

	// Извлечение содержимого ответа
	content := result["choices"].([]interface{})[0].(map[string]interface{})["message"].(map[string]interface{})["content"].(string)
	return content, nil
}

// Groq обрабатывает запросы к API Groq
func Groq(w http.ResponseWriter, r *http.Request) {
	// Получение токена из куки
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value
	claims := &jwt.StandardClaims{}
	// Парсинг токена и проверка его действительности
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var groqReq GroqRequest
	// Декодирование JSON-данных из тела запроса в структуру GroqRequest
	err = json.NewDecoder(r.Body).Decode(&groqReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Вызов API Groq с текстом запроса
	groqResponse, err := CallGroqAPI(groqReq.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка ответа обратно клиенту
	w.Write([]byte(groqResponse))
}
