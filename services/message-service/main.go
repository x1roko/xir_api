package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var jwtKey []byte
var db *gorm.DB

type Message struct {
	gorm.Model
	UserID uint   `json:"user_id"`
	Text   string `json:"text"`
	IsUser bool   `json:"is_user"`
}

type GroqRequest struct {
	Text string `json:"text"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
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

	db.AutoMigrate(&Message{})

	router := mux.NewRouter()
	router.HandleFunc("/messages", GetMessages).Methods("GET")
	router.HandleFunc("/groq", Groq)

	log.Println("Message Service started at 0.0.0.0:8082")
	log.Fatal(http.ListenAndServe("0.0.0.0:8082", router))
}

func GetMessages(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header not found", http.StatusUnauthorized)
		return
	}

	tokenStr := authHeader[len("Bearer "):]
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(claims.Id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
		return
	}

	var messages []Message
	db.Where("user_id = ?", userID).Order("created_at asc").Find(&messages)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(messages)
}

func CallGroqAPI(text string, history []Message) (<-chan string, <-chan error) {
	url := "https://api.groq.com/openai/v1/chat/completions"
	apiKey := os.Getenv("GROQ_API_KEY")

	var messages []map[string]string
	for _, msg := range history {
		role := "user"
		if !msg.IsUser {
			role = "assistant"
		}
		messages = append(messages, map[string]string{
			"role":    role,
			"content": msg.Text,
		})
	}
	messages = append(messages, map[string]string{
		"role":    "user",
		"content": text,
	})

	jsonData := map[string]interface{}{
		"model":            "llama-3.3-70b-versatile",
		"messages":         messages,
		"stream":           true,
		"temperature":      0.7, // Устанавливаем температуру для более чётких ответов
		"presence_penalty": 0.5, // Устанавливаем presence_penalty для уменьшения повторений
	}

	jsonValue, _ := json.Marshal(jsonData)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonValue))
	if err != nil {
		errChan := make(chan error, 1)
		errChan <- err
		close(errChan)
		return nil, errChan
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		errChan := make(chan error, 1)
		errChan <- err
		close(errChan)
		return nil, errChan
	}

	messageChan := make(chan string)
	errChan := make(chan error, 1)

	go func() {
		defer response.Body.Close()
		scanner := bufio.NewScanner(response.Body)
		var responseBuffer bytes.Buffer

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || line == "data: [DONE]" {
				continue
			}

			// Убираем префикс "data: " и пытаемся распарсить JSON
			line = line[len("data: "):]
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(line), &parsed); err != nil {
				log.Printf("Error parsing JSON: %v", err)
				continue
			}

			// Извлекаем содержимое "delta.content"
			choices := parsed["choices"].([]interface{})
			if len(choices) > 0 {
				delta := choices[0].(map[string]interface{})["delta"].(map[string]interface{})
				if content, ok := delta["content"].(string); ok {
					responseBuffer.WriteString(content)
					messageChan <- content
				}
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- err
		}

		close(messageChan)
		close(errChan)
	}()

	return messageChan, errChan
}

func Groq(w http.ResponseWriter, r *http.Request) {
	// Extract the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header not found", http.StatusUnauthorized)
		return
	}

	tokenStr := authHeader[len("Bearer "):]
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(claims.Id, 10, 64)
	if err != nil {
		http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
		return
	}

	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("WebSocket connection established")

	// Основной канал для обработки соединения
	done := make(chan struct{})

	// Чтение сообщений из WebSocket в отдельной горутине
	go func() {
		defer func() {
			close(done)
			conn.Close() // Закрываем соединение, когда горутина завершится
			log.Println("WebSocket connection closed")
		}()

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Connection error or closed by client: %v", err)
				return
			}

			// Логируем полученное сообщение для отладки
			log.Printf("Received message: %s", message)

			// Проверяем, хочет ли пользователь закрыть соединение
			if string(message) == "close" {
				log.Println("Client requested connection close")
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Connection closed by user"))
				return
			}

			if messageType == websocket.TextMessage {
				var groqReq GroqRequest
				if err := json.Unmarshal(message, &groqReq); err != nil {
					log.Printf("Invalid JSON: %v", err)
					continue
				}

				log.Printf("Received message: %v", groqReq)

				// Сохраняем сообщение от пользователя
				userMessage := Message{
					UserID: uint(userID),
					Text:   groqReq.Text,
					IsUser: true,
				}
				db.Create(&userMessage)

				// Извлекаем историю сообщений
				var history []Message
				db.Where("user_id = ?", userID).Order("created_at asc").Find(&history)

				var wg sync.WaitGroup
				var fullResponse string
				messageChan, errChan := CallGroqAPI(groqReq.Text, history)

				// Передача сообщений от API в WebSocket
				wg.Add(1)
				go func() {
					defer wg.Done()
					for msg := range messageChan {
						fullResponse += msg
						err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
						if err != nil {
							log.Printf("Error writing message: %v", err)
							return
						}
					}
				}()

				// Обрабатываем возможные ошибки из API
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := <-errChan; err != nil {
						log.Printf("Error from API: %v", err)
						conn.WriteMessage(websocket.TextMessage, []byte("Error: "+err.Error()))
					}
				}()

				// Ожидаем завершения всех горутин
				wg.Wait()

				// Сохраняем полный ответ API в базу данных
				apiMessage := Message{
					UserID: uint(userID),
					Text:   fullResponse,
					IsUser: false,
				}
				db.Create(&apiMessage)
			}
		}
	}()

	// Блокируем выполнение функции, пока соединение не будет закрыто
	<-done
}
