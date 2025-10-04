package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"

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

	// รับไฟล์ avatar
	var imagePath string
	file, handler, err := r.FormFile("avatar")
	if err == nil {
		defer file.Close()
		os.MkdirAll("./uploads", os.ModePerm)
		imagePath = "./uploads/" + handler.Filename
		dst, err := os.Create(imagePath)
		if err != nil {
			http.Error(w, `{"error":"cannot save file"}`, http.StatusInternalServerError)
			return
		}
		defer dst.Close()
		_, err = io.Copy(dst, file)
		if err != nil {
			http.Error(w, `{"error":"cannot save file"}`, http.StatusInternalServerError)
			return
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error":"cannot hash password"}`, http.StatusInternalServerError)
		return
	}

	// INSERT ลง DB
	stmt, err := db.Prepare("INSERT INTO user (username, email, password, role, imageUser) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, email, string(hashedPassword), role, imagePath)
	if err != nil {
		http.Error(w, `{"error":"cannot insert user"}`, http.StatusInternalServerError)
		return
	}

	// ส่ง response พร้อม URL ของ avatar
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "User registered successfully",
		"imageUser": imagePath, // เก็บ path หรือ URL
	})
}

// handler สำหรับ login
func loginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// รับ JSON body
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ดึง user จาก DB ตาม email
	var hashedPassword string
	var uid, fullName, role string
	err := db.QueryRow("SELECT uid, username, password, role FROM user WHERE email = ?", input.Email).Scan(&uid, &fullName, &hashedPassword, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Email not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// ตรวจสอบ password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(input.Password))
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Login สำเร็จ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Login successful",
		"uid":       uid,
		"full_name": fullName,
		"email":     input.Email,
		"role":      role,
	})

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
