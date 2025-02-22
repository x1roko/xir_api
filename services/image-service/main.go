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
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

var jwtKey []byte

type KandinskyRequest struct {
	Prompt         string `json:"prompt"`
	Model          int    `json:"model"`
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

	router := mux.NewRouter()
	router.HandleFunc("/generate-image", GenerateImage).Methods("POST")
	router.HandleFunc("/ws/generate-image", HandleWebSocketImageGeneration)

	log.Println("Image Service started at 0.0.0.0:8083")
	log.Fatal(http.ListenAndServe("0.0.0.0:8083", router))
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(images)
}

func waitForGenerationCompletion(uuid string) ([]string, error) {
	const maxAttempts = 10
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
		"numImages": req.Images,
		"width":     req.Width,
		"height":    req.Height,
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
	body.WriteString(fmt.Sprintf("%d", req.Model) + "\r\n")
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

func HandleWebSocketImageGeneration(w http.ResponseWriter, r *http.Request) {
	// Получаем токен из URL параметров
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// Проверяем JWT токен
	claims := &jwt.StandardClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !parsedToken.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Upgrade HTTP connection to WebSocket только после успешной авторизации
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading to WebSocket: %v", err)
		return
	}
	defer conn.Close()

	for {
		// Read message from client
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Parse the request
		var wsMessage WebSocketMessage
		if err := json.Unmarshal(message, &wsMessage); err != nil {
			sendError(conn, "Invalid message format")
			continue
		}

		// Handle image generation request
		if wsMessage.Type == "generate" {
			go handleImageGeneration(conn, wsMessage.Data)
		}
	}
}

func handleImageGeneration(conn *websocket.Conn, req KandinskyRequest) {
	// Send "generating" status
	sendStatus(conn, "generating")

	// Call Kandinsky API
	uuid, err := callKandinskyAPI(req)
	if err != nil {
		sendError(conn, fmt.Sprintf("Error calling Kandinsky API: %v", err))
		return
	}

	// Wait for and check generation status
	const maxAttempts = 20
	const delay = 3 * time.Second

	for i := 0; i < maxAttempts; i++ {
		images, err := checkGenerationStatus(uuid)
		if err != nil {
			sendError(conn, fmt.Sprintf("Error checking generation status: %v", err))
			return
		}

		if len(images) > 0 {
			// Send the generated image
			response := WebSocketMessage{
				Type:   "result",
				Status: "completed",
				Image:  images[0],
			}
			if err := conn.WriteJSON(response); err != nil {
				log.Printf("Error sending image: %v", err)
			}
			return
		}

		time.Sleep(delay)
	}

	sendError(conn, "Generation timed out")
}

func sendStatus(conn *websocket.Conn, status string) {
	response := WebSocketMessage{
		Type:   "status",
		Status: status,
	}
	if err := conn.WriteJSON(response); err != nil {
		log.Printf("Error sending status: %v", err)
	}
}

func sendError(conn *websocket.Conn, errorMsg string) {
	response := WebSocketMessage{
		Type:  "error",
		Error: errorMsg,
	}
	if err := conn.WriteJSON(response); err != nil {
		log.Printf("Error sending error message: %v", err)
	}
}
