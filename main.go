package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/cloudinary/cloudinary-go/v2"              // ✅ import Cloudinary
	"github.com/cloudinary/cloudinary-go/v2/api/uploader" // ✅ import uploader
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

// กำหนดโครงสร้างข้อมูล user (ตรงกับ table user ของคุณ)
type User struct {
	UID       string `json:"uid"`
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	ImageUser string `json:"imageUser"` // ✅ เพิ่ม field
}

var db *sql.DB

func main() {
	// Connection string
	dsn := "66011212075:0934308887@tcp(202.28.34.210:3309)/db66011212075"

	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("Cannot ping database:", err)
	}
	fmt.Println("✅ Connected to database successfully")

	// สร้าง API endpoint
	// สร้าง API endpoint
	http.HandleFunc("/user", withCORS(getUsers))
	http.HandleFunc("/register", withCORS(registerUser))
	http.HandleFunc("/login", withCORS(loginUser))
	http.HandleFunc("/hello", withCORS(helloHandler))
	http.HandleFunc("/userbyuid", withCORS(getUserByUid))

	// หา IP ของเครื่อง
	ip := getLocalIP()
	// url := fmt.Sprintf("http://%s:8080/user", ip)
	// Railway จะให้ PORT ผ่าน environment variable
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // สำหรับรันในเครื่อง
	}

	// เปิด browser อัตโนมัติ
	// openBrowser(url)

	// run server
	// fmt.Printf("🚀 Server started at %s\n", url)
	url := fmt.Sprintf("http://%s:%s/hello", ip, port)
	fmt.Printf("🚀 Server started at %s\n", url)

	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}

// handler ดึงข้อมูล user ทั้งหมด
func getUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT uid, username AS full_name, email, password, role, imageUser FROM user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.UID, &u.FullName, &u.Email, &u.Password, &u.Role, &u.ImageUser); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// หา IPv4 LAN จริง
func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "localhost"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				if ip[0] == 192 || ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
					return ip.String()
				}
			}
		}
	}
	return "localhost"
}

// เปิด browser อัตโนมัติ
func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin": // MacOS
		cmd = "open"
		args = []string{url}
	default: // Linux
		cmd = "xdg-open"
		args = []string{url}
	}

	exec.Command(cmd, args...).Start()
}

// handler ลงทะเบียนผู้ใช้ใหม่
func registerUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	// จำกัดขนาดไฟล์ 10 MB
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, `{"error":"cannot parse form"}`, http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	if role == "" {
		role = "user"
	}

	// ===== Upload avatar to Cloudinary =====
	var imageURL string
	file, handler, err := r.FormFile("avatar")
	if err == nil {
		defer file.Close()

		// สร้าง Cloudinary instance จาก ENV
		cld, _ := cloudinary.NewFromParams(
			os.Getenv("CLOUDINARY_CLOUD_NAME"),
			os.Getenv("CLOUDINARY_API_KEY"),
			os.Getenv("CLOUDINARY_API_SECRET"),
		)

		// สร้างชื่อไฟล์ unique
		publicID := fmt.Sprintf("%d_%s", time.Now().UnixNano(), handler.Filename)

		// อัปโหลดไฟล์
		uploadRes, err := cld.Upload.Upload(r.Context(), file, uploader.UploadParams{
			PublicID: publicID,
			Folder:   "avatars", // โฟลเดอร์ใน Cloudinary
		})
		if err != nil {
			http.Error(w, `{"error":"cannot upload to cloudinary"}`, http.StatusInternalServerError)
			return
		}

		imageURL = uploadRes.SecureURL // ได้ URL ของไฟล์ที่ Cloudinary
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"cannot hash password"}`, http.StatusInternalServerError)
		return
	}

	// INSERT ลง DB (เก็บ URL ไม่ใช่ path local)
	stmt, err := db.Prepare("INSERT INTO user (username, email, password, role, imageUser) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, email, string(hashedPassword), role, imageURL)
	if err != nil {
		http.Error(w, `{"error":"cannot insert user"}`, http.StatusInternalServerError)
		return
	}

	// ส่ง response กลับ
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "User registered successfully",
		"imageUser": imageURL,
	})
}

// handler สำหรับ login
func loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// อ่าน JSON body
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Query user จาก DB
	var uid, username, hashedPassword, role, imageUser string
	err := db.QueryRow(
		"SELECT uid, username, password, role, imageUser FROM user WHERE email = ?",
		input.Email,
	).Scan(&uid, &username, &hashedPassword, &role, &imageUser)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"email not found"}`, http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}

	// ตรวจสอบ password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(input.Password)); err != nil {
		http.Error(w, `{"error":"incorrect password"}`, http.StatusUnauthorized)
		return
	}

	// Login สำเร็จ ส่ง response ตรงกับ LoginResponse
	response := map[string]interface{}{
		"message":   "Login successful",
		"uid":       uid,
		"full_name": username,
		"email":     input.Email,
		"role":      role,
		"imageUser": imageUser, // path หรือ URL ของ avatar
	}

	json.NewEncoder(w).Encode(response)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Hello GameShop!",
	})
}

// ใส่ไว้บนๆ ของไฟล์
func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// อนุญาตต้นทางจาก Angular dev server
		if origin == "http://localhost:4200" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			// ถ้าจะใช้ cookie/credentials ให้เปิดบรรทัดนี้และอย่าใช้ "*" เป็น origin
			// w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// ตอบ preflight ทันที
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent) // 204
			return
		}

		h.ServeHTTP(w, r)
	}
}

// handler ดึงข้อมูลผู้ใช้ตาม UID
func getUserByUid(w http.ResponseWriter, r *http.Request) {
	// รับ uid จาก query parameter ?uid=xxx
	uid := r.URL.Query().Get("uid")
	if uid == "" {
		http.Error(w, `{"error":"uid is required"}`, http.StatusBadRequest)
		return
	}

	var user User
	err := db.QueryRow(
		"SELECT uid, username AS full_name, email, role, imageUser FROM user WHERE uid = ?",
		uid,
	).Scan(&user.UID, &user.FullName, &user.Email, &user.Role, &user.ImageUser)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
