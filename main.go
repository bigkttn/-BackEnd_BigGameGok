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
	"strconv"
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
	http.HandleFunc("/editprofile", withCORS(editProfile))
	http.HandleFunc("/games", withCORS(getGames))        // ✅ เพิ่มบรรทัดนี้
	http.HandleFunc("/deletegame", withCORS(deleteGame)) // ✅ Changed from "/games/"

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

		cld, _ := cloudinary.NewFromParams(
			os.Getenv("CLOUDINARY_CLOUD_NAME"),
			os.Getenv("CLOUDINARY_API_KEY"),
			os.Getenv("CLOUDINARY_API_SECRET"),
		)

		publicID := fmt.Sprintf("%d_%s", time.Now().UnixNano(), handler.Filename)

		uploadRes, err := cld.Upload.Upload(r.Context(), file, uploader.UploadParams{
			PublicID: publicID,
			Folder:   "avatars",
		})
		if err != nil {
			http.Error(w, `{"error":"cannot upload to cloudinary"}`, http.StatusInternalServerError)
			return
		}

		imageURL = uploadRes.SecureURL
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

	res, err := stmt.Exec(username, email, string(hashedPassword), role, imageURL)
	if err != nil {
		http.Error(w, `{"error":"cannot insert user"}`, http.StatusInternalServerError)
		return
	}

	// ดึง UID ของผู้ใช้ที่เพิ่งสร้าง
	userID, err := res.LastInsertId()
	if err != nil {
		http.Error(w, `{"error":"cannot get user id"}`, http.StatusInternalServerError)
		return
	}

	// สร้าง response object
	user := map[string]interface{}{
		"uid":       fmt.Sprintf("%d", userID),
		"username":  username,
		"email":     email,
		"role":      role,
		"imageUser": imageURL,
	}

	// ส่ง JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
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

// withCORS ปรับปรุงให้รองรับหลาย origin
func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// whitelist origins ที่อนุญาต
		allowedOrigins := []string{
			"http://localhost:4200",
			"http://localhost:3000",
			"http://localhost:51560",
			"https://your-frontend-domain.com", // ใส่ domain ของ frontend production ตรงนี้
		}

		// ตรวจสอบว่า origin ที่ส่งมาถูก whitelist ไว้หรือไม่
		for _, o := range allowedOrigins {
			if origin == o {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				break
			}
		}

		// กำหนด method และ header ที่อนุญาต
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// ตอบ preflight request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
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

// handler สำหรับแก้ไขโปรไฟล์
func editProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// จำกัดขนาดไฟล์ 10 MB
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, `{"error":"cannot parse form"}`, http.StatusBadRequest)
		return
	}

	uid := r.FormValue("uid")
	fullName := r.FormValue("full_name")
	email := r.FormValue("email")
	role := r.FormValue("role")

	// ===== Upload avatar ใหม่ถ้ามี =====
	var imageURL string
	file, _, err := r.FormFile("avatar")
	if err == nil {
		defer file.Close()

		cld, _ := cloudinary.NewFromParams(
			os.Getenv("CLOUDINARY_CLOUD_NAME"),
			os.Getenv("CLOUDINARY_API_KEY"),
			os.Getenv("CLOUDINARY_API_SECRET"),
		)

		publicID := fmt.Sprintf("avatar_%s_%d", uid, time.Now().UnixNano())
		overwrite := true

		uploadRes, err := cld.Upload.Upload(r.Context(), file, uploader.UploadParams{
			PublicID:  publicID,
			Folder:    "avatars",
			Overwrite: &overwrite,
		})
		if err != nil {
			http.Error(w, `{"error":"cannot upload avatar"}`, http.StatusInternalServerError)
			return
		}
		imageURL = uploadRes.SecureURL
	}

	// ===== Update DB =====
	// ถ้าไม่มีรูปใหม่ ให้คงค่าเดิม
	query := "UPDATE user SET username=?, email=?, role=?"
	args := []interface{}{fullName, email, role}

	if imageURL != "" {
		query += ", imageUser=?"
		args = append(args, imageURL)
	}

	query += " WHERE uid=?"
	args = append(args, uid)

	stmt, err := db.Prepare(query)
	if err != nil {
		http.Error(w, `{"error":"database error"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(args...)
	if err != nil {
		http.Error(w, `{"error":"cannot update user"}`, http.StatusInternalServerError)
		return
	}

	// ส่ง response กลับ
	response := map[string]interface{}{
		"message":   "Profile updated successfully",
		"uid":       uid,
		"full_name": fullName,
		"email":     email,
		"role":      role,
		"imageUser": imageURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// กำหนดโครงสร้างข้อมูล game (ตรงกับ table game ของคุณ)
type Game struct {
	GameID      int     `json:"game_id"`
	GameName    string  `json:"game_name"`
	Price       float64 `json:"price"`
	Image       *string `json:"image"` // ใช้ pointer (*string) เพราะค่าอาจเป็น NULL
	Description *string `json:"description"`
	ReleaseDate *string `json:"release_date"`
	Sold        *int    `json:"sold"`
	TypeID      *int    `json:"type_id"`
	UserID      *int    `json:"user_id"`
}

// handler ดึงข้อมูล game ทั้งหมด
func getGames(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT game_id, game_name, price, image, description, release_date, sold, type_id, user_id FROM game")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var games []Game
	for rows.Next() {
		var g Game
		// เนื่องจากบาง field อาจเป็น NULL เราจึงใช้ pointer ในการ Scan
		if err := rows.Scan(&g.GameID, &g.GameName, &g.Price, &g.Image, &g.Description, &g.ReleaseDate, &g.Sold, &g.TypeID, &g.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, g)
	}

	// ตรวจสอบ error ที่อาจเกิดขึ้นระหว่างวนลูป
	if err = rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(games)
}

// handler to delete a game by its ID (updated for new endpoint)
func deleteGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ✅ Get the game_id from a query parameter, e.g., /deletegame?id=12
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Query parameter 'id' is required"}`, http.StatusBadRequest)
		return
	}

	// The rest of the function remains the same
	stmt, err := db.Prepare("DELETE FROM game WHERE game_id = ?")
	if err != nil {
		http.Error(w, `{"error":"Database error preparing statement"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(id)
	if err != nil {
		http.Error(w, `{"error":"Failed to execute deletion"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		http.Error(w, `{"error":"Failed to check affected rows"}`, http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, `{"error":"Game not found with the given ID"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Game with ID %s deleted successfully", id),
	})
}

// This struct is for creating a new game (omits GameID)
type NewGame struct {
	GameName    string  `json:"game_name"`
	Price       float64 `json:"price"`
	Image       *string `json:"image"`
	Description *string `json:"description"`
	ReleaseDate *string `json:"release_date"`
	TypeID      int     `json:"type_id"`
	UserID      int     `json:"user_id"`
}

// handler to add a new game (with image upload)
func addGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ✅ 1. Parse multipart form data (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, `{"error":"cannot parse form"}`, http.StatusBadRequest)
		return
	}

	// ✅ 2. Get form values as strings
	gameName := r.FormValue("game_name")
	priceStr := r.FormValue("price")
	description := r.FormValue("description")
	releaseDate := r.FormValue("release_date")
	typeIDStr := r.FormValue("type_id")
	userIDStr := r.FormValue("user_id")

	// ✅ 3. Convert string values to correct types
	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid price format"}`, http.StatusBadRequest)
		return
	}
	typeID, err := strconv.Atoi(typeIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid type_id format"}`, http.StatusBadRequest)
		return
	}
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid user_id format"}`, http.StatusBadRequest)
		return
	}

	// ✅ 4. Upload image to Cloudinary (if it exists)
	var imageURL string
	file, handler, err := r.FormFile("image") // Use "image" as the field name
	if err == nil {                           // A file was included
		defer file.Close()
		cld, _ := cloudinary.NewFromParams(
			os.Getenv("CLOUDINARY_CLOUD_NAME"),
			os.Getenv("CLOUDINARY_API_KEY"),
			os.Getenv("CLOUDINARY_API_SECRET"),
		)
		publicID := fmt.Sprintf("game_%s_%d", handler.Filename, time.Now().UnixNano())
		uploadRes, err := cld.Upload.Upload(r.Context(), file, uploader.UploadParams{
			PublicID: publicID,
			Folder:   "games", // Store in a "games" folder
		})
		if err != nil {
			http.Error(w, `{"error":"cannot upload image to cloudinary"}`, http.StatusInternalServerError)
			return
		}
		imageURL = uploadRes.SecureURL
	}

	// ✅ 5. Insert into the database
	stmt, err := db.Prepare("INSERT INTO game(game_name, price, image, description, release_date, type_id, user_id) VALUES(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, `{"error":"database error preparing statement"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(gameName, price, imageURL, description, releaseDate, typeID, userID)
	if err != nil {
		http.Error(w, `{"error":"failed to insert game"}`, http.StatusInternalServerError)
		return
	}

	newID, err := res.LastInsertId()
	if err != nil {
		http.Error(w, `{"error":"failed to retrieve last insert ID"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Game added successfully",
		"game_id": newID,
	})
}
