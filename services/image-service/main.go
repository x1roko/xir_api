package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"path/filepath"

	"context"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	jwtKey []byte
	db     *gorm.DB
)

type KandinskyRequest struct {
	Prompt         string `json:"prompt"`
	Images         int    `json:"images"`
	Width          int    `json:"width"`
	Height         int    `json:"height"`
	Style          string `json:"style"`
	NegativePrompt string `json:"negativePrompt"`
}

type KandinskyResponse struct {
	UUID string `json:"uuid"`
}

type CheckStatusResponse struct {
	UUID             string   `json:"uuid"`
	Status           string   `json:"status"`
	Images           []string `json:"images"`
	ErrorDescription string   `json:"errorDescription"`
	Censored         bool     `json:"censored"`
}

type WebSocketMessage struct {
	Type   string           `json:"type"`
	Status string           `json:"status"`
	Data   KandinskyRequest `json:"data,omitempty"`
	Image  string           `json:"image,omitempty"`
	Error  string           `json:"error,omitempty"`
}

type Message struct {
	gorm.Model
	UserID      uint   `gorm:"index"`
	Prompt      string `json:"prompt"`
	IsGenerated bool   `json:"is_generated"`
	CreatedAt   time.Time
}

type Image struct {
	Filename       string `gorm:"primaryKey" json:"filename"`
	UserID         uint   `gorm:"index" json:"user_id"`
	Prompt         string `json:"prompt"`
	IsUser         bool   `json:"is_user"`
	Width          int    `json:"width"`
	Height         int    `json:"height"`
	Style          string `json:"style"`
	NegativePrompt string `json:"negative_prompt"`
	Status         string `json:"status"`
	CreatedAt      time.Time
}

type DialogHistoryItem struct {
	UserRequest Image     `json:"user_request"`
	SystemImage Image     `json:"system_image"`
	CreatedAt   time.Time `json:"created_at"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем подключения с любых источников
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

	err = db.AutoMigrate(&Message{}, &Image{})
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/generate-image", GenerateImage).Methods("POST")
	router.HandleFunc("/get-message-history", GetMessageHistory).Methods("GET")

	// Добавляем middleware для аутентификации WebSocket
	router.HandleFunc("/ws/generate-image", authenticateWebSocket(HandleWebSocketImageGeneration))

	// Новый эндпоинт для получения изображений
	router.HandleFunc("/get-image", serveImage).Methods("GET")

	log.Println("Image Service started at 0.0.0.0:8083")
	log.Fatal(http.ListenAndServe("0.0.0.0:8083", router))
}

func authenticateWebSocket(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		// Сохраняем UserID в контексте запроса для дальнейшего использования
		ctx := context.WithValue(r.Context(), "userID", claims.Id)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

func GenerateImage(w http.ResponseWriter, r *http.Request) {
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

	userID, err := strconv.ParseUint(claims.Id, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var kandinskyReq KandinskyRequest
	err = json.NewDecoder(r.Body).Decode(&kandinskyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	uuid, err := callKandinskyAPI(kandinskyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	images, err := waitForGenerationCompletion(uuid)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Сохраняем изображения
	var savedImages []string
	for idx, base64Image := range images {
		filename := fmt.Sprintf("image_%s_%d_%d.png", uuid, time.Now().UnixNano(), idx)

		imagePath := filepath.Join(os.Getenv("IMAGES_STORAGE_PATH"), filename)

		// Удаляем префикс base64, если он есть
		base64Data := base64Image
		if strings.Contains(base64Image, ",") {
			base64Data = strings.Split(base64Image, ",")[1]
		}

		imageData, err := base64.StdEncoding.DecodeString(base64Data)
		if err != nil {
			log.Printf("Error decoding base64 image: %v", err)
			continue
		}

		err = os.WriteFile(imagePath, imageData, 0644)
		if err != nil {
			log.Printf("Error saving image file: %v", err)
			continue
		}

		// Создаем запись в базе данных
		img := Image{
			Filename:       filename,
			UserID:         uint(userID),
			Prompt:         kandinskyReq.Prompt,
			IsUser:         true,
			Width:          kandinskyReq.Width,
			Height:         kandinskyReq.Height,
			Style:          kandinskyReq.Style,
			NegativePrompt: kandinskyReq.NegativePrompt,
			Status:         "generated",
		}
		db.Create(&img)

		savedImages = append(savedImages, filename)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(savedImages)
}

func HandleWebSocketImageGeneration(w http.ResponseWriter, r *http.Request) {
	// Получаем UserID из контекста
	userID := r.Context().Value("userID").(string)
	userIDUint, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	for {
		var msg WebSocketMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		switch msg.Type {
		case "generate":
			// Генерируем изображение через Kandinsky API
			uuid, err := callKandinskyAPI(msg.Data)
			if err != nil {
				conn.WriteJSON(WebSocketMessage{
					Type:  "error",
					Error: "Failed to generate image: " + err.Error(),
				})
				continue
			}

			// Ожидаем завершения генерации
			images, err := waitForGenerationCompletion(uuid)
			if err != nil {
				conn.WriteJSON(WebSocketMessage{
					Type:  "error",
					Error: "Image generation failed: " + err.Error(),
				})
				continue
			}

			// Сохраняем изображения
			var savedImages []string
			for idx, base64Image := range images {
				filename := fmt.Sprintf("image_%s_%d_%d.png", uuid, time.Now().UnixNano(), idx)

				imagePath := filepath.Join(os.Getenv("IMAGES_STORAGE_PATH"), filename)

				// Удаляем префикс base64, если он есть
				base64Data := base64Image
				if strings.Contains(base64Image, ",") {
					base64Data = strings.Split(base64Image, ",")[1]
				}

				imageData, err := base64.StdEncoding.DecodeString(base64Data)
				if err != nil {
					log.Printf("Error decoding base64 image: %v", err)
					continue
				}

				err = os.WriteFile(imagePath, imageData, 0644)
				if err != nil {
					log.Printf("Error saving image file: %v", err)
					continue
				}

				// Создаем запись в базе данных
				img := Image{
					Filename:       filename,
					UserID:         uint(userIDUint),
					Prompt:         msg.Data.Prompt,
					IsUser:         false, // Сгенерировано системой
					Width:          msg.Data.Width,
					Height:         msg.Data.Height,
					Style:          msg.Data.Style,
					NegativePrompt: msg.Data.NegativePrompt,
					Status:         "generated",
				}
				db.Create(&img)

				savedImages = append(savedImages, filename)
			}

			// Отправляем результат обратно клиенту
			err = conn.WriteJSON(WebSocketMessage{
				Type:   "result",
				Status: "success",
				Data:   msg.Data,
				Image:  savedImages[0], // Отправляем первое изображение
			})
			if err != nil {
				log.Printf("Error sending WebSocket message: %v", err)
			}

		default:
			conn.WriteJSON(WebSocketMessage{
				Type:  "error",
				Error: "Unknown message type",
			})
		}
	}
}

func GetMessageHistory(w http.ResponseWriter, r *http.Request) {
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

	userID, err := strconv.ParseUint(claims.Id, 10, 32)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Получаем все изображения пользователя
	var userImages []Image
	result := db.Where("user_id = ?", userID).Order("created_at ASC").Find(&userImages)
	if result.Error != nil {
		http.Error(w, "Failed to retrieve images", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userImages)
}

func waitForGenerationCompletion(uuid string) ([]string, error) {
	const maxAttempts = 100
	const delay = 5 * time.Second

	for i := 0; i < maxAttempts; i++ {
		images, err := checkGenerationStatus(uuid)
		if err != nil {
			return nil, err
		}

		if len(images) > 0 {
			return images, nil
		}

		time.Sleep(delay)
	}

	return nil, fmt.Errorf("generation failed after %d attempts", maxAttempts)
}

func callKandinskyAPI(req KandinskyRequest) (string, error) {
	url := "https://api-key.fusionbrain.ai/key/api/v1/text2image/run"
	apiKey := os.Getenv("KANDINSKY_API_KEY")
	secretKey := os.Getenv("KANDINSKY_SECRET_KEY")

	params := map[string]interface{}{
		"type":      "GENERATE",
		"style":     req.Style,
		"width":     req.Width,
		"height":    req.Height,
		"numImages": req.Images,
		//"model_id":  4, // Захардкоженная модель
		"generateParams": map[string]interface{}{
			"query": req.Prompt,
		},
	}

	if req.Style != "" {
		params["style"] = req.Style
	}
	if req.NegativePrompt != "" {
		params["negativePromptUnclip"] = req.NegativePrompt
	}

	jsonValue, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	boundary := "----WebKitFormBoundary" + strings.ReplaceAll(fmt.Sprintf("%x", os.Getpid()), "-", "")

	var body bytes.Buffer
	body.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	body.WriteString("Content-Disposition: form-data; name=\"model_id\"\r\n\r\n")
	body.WriteString("4\r\n") // Захардкоженная модель
	body.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	body.WriteString("Content-Disposition: form-data; name=\"params\"\r\n")
	body.WriteString("Content-Type: application/json\r\n\r\n")
	body.WriteString(string(jsonValue) + "\r\n")
	body.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	request, err := http.NewRequest("POST", url, &body)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	request.Header.Set("X-Key", "Key "+apiKey)
	request.Header.Set("X-Secret", "Secret "+secretKey)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	log.Printf("Full Kandinsky API Response: %s", string(responseBody))

	var generateResponse KandinskyResponse
	if err := json.Unmarshal(responseBody, &generateResponse); err != nil {
		return "", err
	}

	return generateResponse.UUID, nil
}

func checkGenerationStatus(uuid string) ([]string, error) {
	url := fmt.Sprintf("https://api-key.fusionbrain.ai/key/api/v1/text2image/status/%s", uuid)
	apiKey := os.Getenv("KANDINSKY_API_KEY")
	secretKey := os.Getenv("KANDINSKY_SECRET_KEY")

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Key", "Key "+apiKey)
	request.Header.Set("X-Secret", "Secret "+secretKey)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var statusResponse CheckStatusResponse
	if err := json.NewDecoder(response.Body).Decode(&statusResponse); err != nil {
		return nil, err
	}

	log.Printf("Kandinsky Status Response: %+v", statusResponse)

	if statusResponse.Status == "DONE" {
		for i, imageData := range statusResponse.Images {
			filename := fmt.Sprintf("/app/images/image_%s_%d.png", uuid, i)
			if err := saveBase64Image(imageData, filename); err != nil {
				return nil, err
			}
		}
		return statusResponse.Images, nil
	}

	return nil, nil
}

func saveBase64Image(base64String, filename string) error {
	base64Data := strings.Replace(base64String, "data:image/png;base64,", "", 1)

	imageData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, strings.NewReader(string(imageData)))
	if err != nil {
		return err
	}

	return nil
}

func serveImage(w http.ResponseWriter, r *http.Request) {
	// Получаем имя файла из URL
	filename := r.URL.Query().Get("filename")

	// Проверяем, что файл существует
	imagePath := filepath.Join(os.Getenv("IMAGES_STORAGE_PATH"), filename)
	if _, err := os.Stat(imagePath); os.IsNotExist(err) {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	// Отправляем изображение
	http.ServeFile(w, r, imagePath)
}
