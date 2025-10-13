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
	"strings"
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
	http.HandleFunc("/addGame", withCORS(addGame))
	http.HandleFunc("/typegames", withCORS(getTypeGames))
	http.HandleFunc("/game", withCORS(getGameByID))            // สำหรับดึงเกมเดียว
	http.HandleFunc("/editgame", withCORS(editGame))           // สำหรับอัปเดตเกม
	http.HandleFunc("/wallet/add", withCORS(addFundsToWallet)) // เพิ่มเงินเข้ากระเป๋า
	http.HandleFunc("/wallet", withCORS(getWalletByUserID))    // ดึงข้อมูลเงินในกระเป๋าตาม user_id
	http.HandleFunc("/wallet-history", withCORS(getWalletHistory))
	http.HandleFunc("/discount-codes", withCORS(getDiscountCodesHandler))           // ✅ GET (ทั้งหมด): ดึงโค้ดส่วนลดทั้งหมด
	http.HandleFunc("/discount-codes/add", withCORS(addDiscountCodeHandler))        // ✅ POST: สร้างโค้ดส่วนลดใหม่
	http.HandleFunc("/discount-codes/get/", withCORS(getDiscountCodeByIDHandler))   // ✅ GET (ชิ้นเดียว): ดึงโค้ดส่วนลดตาม ID
	http.HandleFunc("/discount-codes/update/", withCORS(updateDiscountCodeHandler)) // ✅ PUT: แก้ไขโค้ดส่วนลดตาม ID
	http.HandleFunc("/discount-codes/delete/", withCORS(deleteDiscountCodeHandler)) // ✅ DELETE: ลบโค้ดส่วนลดตาม ID
	http.HandleFunc("/purchase-history", withCORS(getPurchaseHistoryHandler))       // ประวัติการซื้อเกม
	http.HandleFunc("/buygame", withCORS(buyGame))                                  // ซื้อเกม
	http.HandleFunc("/searchgames", withCORS(searchGames))                          // ค้นหาเกม/ Knn
	http.HandleFunc("/user-library", withCORS(getUserLibraryHandler))               // ดึงคลังเกมของผู้ใช้

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

	// INSERT ลง DB (user)
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

	// สร้าง wallet เริ่มต้นสำหรับผู้ใช้ใหม่
	walletStmt, err := db.Prepare("INSERT INTO wallet (cash, user_id) VALUES (?, ?)")
	if err != nil {
		// ใน production จริง อาจจะต้องมีการจัดการ error ที่ซับซ้อนกว่านี้ เช่นลบ user ที่เพิ่งสร้างไป
		http.Error(w, `{"error":"database error on wallet creation"}`, http.StatusInternalServerError)
		return
	}
	defer walletStmt.Close()

	// กำหนดค่าเริ่มต้น cash = 0.00 และใช้ userID ที่ได้มา
	_, err = walletStmt.Exec(0.00, userID)
	if err != nil {
		http.Error(w, `{"error":"cannot insert wallet"}`, http.StatusInternalServerError)
		return
	}
	// ==========================================================

	// สร้าง response object
	user := map[string]interface{}{
		"uid":       fmt.Sprintf("%d", userID),
		"username":  username,
		"email":     email,
		"role":      role,
		"imageUser": imageURL,
		// เพิ่มข้อมูล cash เริ่มต้นใน response ด้วยก็ได้
		"cash": 0.00,
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

// handler to add a new game (with image upload)
func addGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse multipart form data (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, `{"error":"cannot parse form"}`, http.StatusBadRequest)
		return
	}

	// 2. Get form values as strings
	gameName := r.FormValue("game_name")
	priceStr := r.FormValue("price")
	description := r.FormValue("description")
	// releaseDate := r.FormValue("release_date") // <<< ไม่ได้รับค่าวันที่จากฟอร์มแล้ว
	typeIDStr := r.FormValue("type_id")
	userIDStr := r.FormValue("user_id")

	// ==================== ✅ ส่วนที่แก้ไข ====================
	// สร้างวันที่ปัจจุบันในรูปแบบที่ SQL เข้าใจ (YYYY-MM-DD)
	releaseDate := time.Now().Format("2006-01-02")
	// ========================================================

	// 3. Convert string values to correct types
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

	// 4. Upload image to Cloudinary (if it exists)
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

	// 5. Insert into the database
	stmt, err := db.Prepare("INSERT INTO game(game_name, price, image, description, release_date, type_id, user_id) VALUES(?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, `{"error":"database error preparing statement"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	// สังเกตว่าตัวแปร releaseDate ที่ส่งเข้าไปตอนนี้คือค่าวันที่ปัจจุบัน
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

type TypeGame struct {
	TypeID   int    `json:"type_id"`
	TypeName string `json:"type_name"`
}

// ✅ 2. Handler function to get all game types from the 'typegame' table
func getTypeGames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ✅ The only change is here: "FROM type" becomes "FROM typegame"
	rows, err := db.Query("SELECT type_id, type_name FROM typegame ORDER BY type_id ASC")
	if err != nil {
		http.Error(w, `{"error":"Database query error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var typeGames []TypeGame
	for rows.Next() {
		var tg TypeGame
		if err := rows.Scan(&tg.TypeID, &tg.TypeName); err != nil {
			http.Error(w, `{"error":"Failed to scan row"}`, http.StatusInternalServerError)
			return
		}
		typeGames = append(typeGames, tg)
	}

	if err = rows.Err(); err != nil {
		http.Error(w, `{"error":"Error iterating over rows"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(typeGames)
}

// handler ดึงข้อมูลเกมเดียวตาม ID
func getGameByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// รับ game_id จาก query parameter e.g., /game?id=1
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"Query parameter 'id' is required"}`, http.StatusBadRequest)
		return
	}

	var g Game
	// ใช้ QueryRow เพราะเราคาดหวังผลลัพธ์แค่แถวเดียว
	err := db.QueryRow("SELECT game_id, game_name, price, image, description, release_date, sold, type_id, user_id FROM game WHERE game_id = ?", id).Scan(&g.GameID, &g.GameName, &g.Price, &g.Image, &g.Description, &g.ReleaseDate, &g.Sold, &g.TypeID, &g.UserID)

	if err != nil {
		if err == sql.ErrNoRows {
			// ถ้าไม่เจอเกม ID นี้ในระบบ
			http.Error(w, `{"error":"Game not found"}`, http.StatusNotFound)
			return
		}
		// Error อื่นๆ
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(g)
}

// handler สำหรับแก้ไขข้อมูลเกม
func editGame(w http.ResponseWriter, r *http.Request) {
	// ใช้ Method PUT สำหรับการอัปเดตข้อมูล
	if r.Method != http.MethodPut {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. Parse multipart form data (เผื่อมีการอัปโหลดรูปใหม่)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, `{"error":"cannot parse form"}`, http.StatusBadRequest)
		return
	}

	// 2. ดึงค่าจากฟอร์มที่ส่งมา
	gameIDStr := r.FormValue("game_id")
	gameName := r.FormValue("game_name")
	priceStr := r.FormValue("price")
	description := r.FormValue("description")
	typeIDStr := r.FormValue("type_id")

	// 3. แปลงค่าที่จำเป็นให้เป็นตัวเลข
	gameID, err := strconv.Atoi(gameIDStr)
	if err != nil {
		http.Error(w, `{"error":"invalid game_id format"}`, http.StatusBadRequest)
		return
	}
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

	// 4. ตรวจสอบและอัปโหลดรูปใหม่ (ถ้ามี)
	var newImageURL string
	file, _, err := r.FormFile("image")
	if err == nil { // ถ้ามีไฟล์ใหม่ถูกส่งมาด้วย
		defer file.Close()
		cld, _ := cloudinary.NewFromParams(
			os.Getenv("CLOUDINARY_CLOUD_NAME"),
			os.Getenv("CLOUDINARY_API_KEY"),
			os.Getenv("CLOUDINARY_API_SECRET"),
		)
		publicID := fmt.Sprintf("game_updated_%d_%d", gameID, time.Now().UnixNano())
		uploadRes, err := cld.Upload.Upload(r.Context(), file, uploader.UploadParams{
			PublicID: publicID,
			Folder:   "games",
		})
		if err != nil {
			http.Error(w, `{"error":"cannot upload new image"}`, http.StatusInternalServerError)
			return
		}
		newImageURL = uploadRes.SecureURL
	}

	// 5. สร้างคำสั่ง SQL แบบ Dynamic
	query := "UPDATE game SET game_name=?, price=?, description=?, type_id=?"
	args := []interface{}{gameName, price, description, typeID}

	if newImageURL != "" {
		query += ", image=?"
		args = append(args, newImageURL)
	}

	query += " WHERE game_id=?"
	args = append(args, gameID)

	// 6. Execute คำสั่ง SQL
	stmt, err := db.Prepare(query)
	if err != nil {
		http.Error(w, `{"error":"database error preparing statement"}`, http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	res, err := stmt.Exec(args...)
	if err != nil {
		http.Error(w, `{"error":"failed to update game"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"error":"game not found with the given id"}`, http.StatusNotFound)
		return
	}

	// 7. ส่ง Response กลับไป
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Game updated successfully",
		"game_id": gameID,
	})
}

// AddFundsRequest defines the structure for the JSON body of the add funds request
type AddFundsRequest struct {
	UserID int     `json:"user_id"`
	Amount float64 `json:"amount"`
}
type Wallet struct {
	WID    int     `json:"wid"`
	Cash   float64 `json:"cash"`
	UserID int     `json:"user_id"`
}

// addFundsToWallet handles adding funds to a user's wallet
func addFundsToWallet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. อ่านข้อมูล JSON จาก request body
	var req AddFundsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// ตรวจสอบว่าจำนวนเงินที่ส่งมาถูกต้อง
	if req.Amount <= 0 {
		http.Error(w, `{"error":"Amount must be positive"}`, http.StatusBadRequest)
		return
	}

	// 2. เริ่มต้น Transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, `{"error":"Cannot start transaction"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// 3. ค้นหา wallet ID (wid) จาก user_id
	var wid int
	err = tx.QueryRow("SELECT wid FROM wallet WHERE user_id = ?", req.UserID).Scan(&wid)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"Wallet for the given user not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Database error finding wallet"}`, http.StatusInternalServerError)
		return
	}

	// 4. อัปเดตยอดเงินในตาราง wallet
	_, err = tx.Exec("UPDATE wallet SET cash = cash + ? WHERE wid = ?", req.Amount, wid)
	if err != nil {
		http.Error(w, `{"error":"Failed to update wallet balance"}`, http.StatusInternalServerError)
		return
	}

	// 5. เพิ่มประวัติการทำธุรกรรม (เวอร์ชันแก้ไข)
	// ✅ 1. แก้ไข SQL: เอาคอลัมน์ hid ออก
	historyStmt, err := tx.Prepare("INSERT INTO historywallet (date, amount, wid) VALUES (?, ?, ?)")
	if err != nil {
		http.Error(w, `{"error":"Failed to prepare history statement"}`, http.StatusInternalServerError)
		return
	}
	defer historyStmt.Close()

	currentDate := time.Now().Format("2006-01-02")
	// ✅ 2. แก้ไข Exec: เอา parameter ของ hid (Unix timestamp) ออก
	_, err = historyStmt.Exec(currentDate, req.Amount, wid)
	if err != nil {
		http.Error(w, `{"error":"Failed to insert into historywallet"}`, http.StatusInternalServerError)
		return
	}

	// 6. ถ้าทุกอย่างสำเร็จ ให้ Commit Transaction
	if err := tx.Commit(); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
		return
	}

	// 7. ส่ง Response กลับไป
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Funds added successfully",
		"user_id":      req.UserID,
		"added_amount": req.Amount,
	})
}

// getWalletByUserID handles fetching wallet data for a specific user
func getWalletByUserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// รับ user_id จาก query parameter e.g., /wallet?user_id=1
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, `{"error":"Query parameter 'user_id' is required"}`, http.StatusBadRequest)
		return
	}

	var wallet Wallet
	// Query ข้อมูลจากตาราง wallet โดยใช้ user_id
	err := db.QueryRow("SELECT wid, cash, user_id FROM wallet WHERE user_id = ?", userID).Scan(&wallet.WID, &wallet.Cash, &wallet.UserID)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"Wallet not found for this user"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wallet)
}

type WalletHistory struct {
	HID    int     `json:"hid"`
	Date   string  `json:"date"`
	Amount float64 `json:"amount"`
	WID    int     `json:"wid"`
}

func getWalletHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, `{"error":"Query parameter 'user_id' is required"}`, http.StatusBadRequest)
		return
	}

	query := `
		SELECT h.hid, DATE_FORMAT(h.date, '%Y-%m-%d'), h.amount, h.wid
		FROM historywallet h
		JOIN wallet w ON h.wid = w.wid
		WHERE w.user_id = ?
		ORDER BY h.date DESC, h.hid DESC
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		http.Error(w, `{"error":"Database query error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var history []WalletHistory
	for rows.Next() {
		var item WalletHistory
		if err := rows.Scan(&item.HID, &item.Date, &item.Amount, &item.WID); err != nil {
			http.Error(w, `{"error":"Failed to scan row"}`, http.StatusInternalServerError)
			return
		}
		history = append(history, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

type DiscountCode struct {
	CodeID        int     `json:"code_id"`
	Code          string  `json:"code"`
	DiscountType  string  `json:"discount_type"` // 'percentage' or 'fixed'
	DiscountValue float64 `json:"discount_value"`
	// ใช้ pointer เพราะค่าอาจเป็น NULL
	ExpiryDate *time.Time `json:"expiry_date"`
	UsageLimit int        `json:"usage_limit"`
	TimesUsed  int        `json:"times_used"`
	IsActive   bool       `json:"is_active"`
}

// --- 1. Handler สำหรับ GET (ดึงข้อมูลทั้งหมด) ---
func getDiscountCodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query("SELECT code_id, code, discount_type, discount_value, expiry_date, usage_limit, times_used, is_active FROM discount_codes ORDER BY code_id DESC")
	if err != nil {
		http.Error(w, `{"error":"Database query error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var codes []DiscountCode
	for rows.Next() {
		var dc DiscountCode
		if err := rows.Scan(&dc.CodeID, &dc.Code, &dc.DiscountType, &dc.DiscountValue, &dc.ExpiryDate, &dc.UsageLimit, &dc.TimesUsed, &dc.IsActive); err != nil {
			http.Error(w, `{"error":"Failed to scan row"}`, http.StatusInternalServerError)
			return
		}
		codes = append(codes, dc)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

// --- 2. Handler สำหรับ POST (เพิ่มข้อมูล) ---
func addDiscountCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var newCode DiscountCode
	if err := json.NewDecoder(r.Body).Decode(&newCode); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	_, err := db.Exec(
		"INSERT INTO discount_codes (code, discount_type, discount_value, expiry_date, usage_limit, is_active) VALUES (?, ?, ?, ?, ?, ?)",
		newCode.Code, newCode.DiscountType, newCode.DiscountValue, newCode.ExpiryDate, newCode.UsageLimit, newCode.IsActive,
	)
	if err != nil {
		http.Error(w, `{"error":"Failed to create discount code"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Discount code created successfully"})
}

// --- 3. Handler สำหรับ GET (ดึงข้อมูลชิ้นเดียวตาม ID) ---
func getDiscountCodeByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ดึง ID จาก URL เช่น /discount-codes/get/123
	idStr := strings.TrimPrefix(r.URL.Path, "/discount-codes/get/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"Invalid ID format"}`, http.StatusBadRequest)
		return
	}

	var dc DiscountCode
	err = db.QueryRow("SELECT code_id, code, discount_type, discount_value, expiry_date, usage_limit, times_used, is_active FROM discount_codes WHERE code_id = ?", id).Scan(&dc.CodeID, &dc.Code, &dc.DiscountType, &dc.DiscountValue, &dc.ExpiryDate, &dc.UsageLimit, &dc.TimesUsed, &dc.IsActive)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"Discount code not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dc)
}

// --- 4. Handler สำหรับ PUT (แก้ไขข้อมูลตาม ID) ---
func updateDiscountCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ดึง ID จาก URL เช่น /discount-codes/update/123
	idStr := strings.TrimPrefix(r.URL.Path, "/discount-codes/update/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"Invalid ID format"}`, http.StatusBadRequest)
		return
	}

	var codeToUpdate DiscountCode
	if err := json.NewDecoder(r.Body).Decode(&codeToUpdate); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	_, err = db.Exec(
		"UPDATE discount_codes SET code=?, discount_type=?, discount_value=?, expiry_date=?, usage_limit=?, is_active=? WHERE code_id=?",
		codeToUpdate.Code, codeToUpdate.DiscountType, codeToUpdate.DiscountValue, codeToUpdate.ExpiryDate, codeToUpdate.UsageLimit, codeToUpdate.IsActive, id,
	)
	if err != nil {
		http.Error(w, `{"error":"Failed to update discount code"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Code updated successfully"})
}

// --- 5. Handler สำหรับ DELETE (ลบข้อมูลตาม ID) ---
func deleteDiscountCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// ดึง ID จาก URL เช่น /discount-codes/delete/123
	idStr := strings.TrimPrefix(r.URL.Path, "/discount-codes/delete/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"Invalid ID format"}`, http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM discount_codes WHERE code_id = ?", id)
	if err != nil {
		http.Error(w, `{"error":"Failed to delete discount code"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Code deleted successfully"})
}

type PurchaseHistoryItem struct {
	GameName string  `json:"game_name"`
	Price    float64 `json:"price"`
	Image    *string `json:"image"` // ใช้ pointer เพราะค่าอาจเป็น NULL
	Date     string  `json:"date"`
}

func getPurchaseHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, `{"error":"Query parameter 'user_id' is required"}`, http.StatusBadRequest)
		return
	}

	// ใช้ SQL JOIN เพื่อดึงข้อมูลจาก 3 ตาราง: orders, order_details, และ game
	query := `
		SELECT 
			g.game_name,
			od.price, 
			g.image,
			DATE_FORMAT(o.order_date, '%Y-%m-%d %H:%i') as purchase_date
		FROM orders o
		JOIN order_details od ON o.order_id = od.order_id
		JOIN game g ON od.game_id = g.game_id
		WHERE o.user_id = ?
		ORDER BY o.order_date DESC
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		http.Error(w, `{"error":"Database query error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var history []PurchaseHistoryItem
	for rows.Next() {
		var item PurchaseHistoryItem
		if err := rows.Scan(&item.GameName, &item.Price, &item.Image, &item.Date); err != nil {
			http.Error(w, `{"error":"Failed to scan row"}`, http.StatusInternalServerError)
			return
		}
		history = append(history, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

type BuyGameRequest struct {
	UserID int `json:"user_id"`
	GameID int `json:"game_id"`
}

// ✅ แก้ไขฟังก์ชัน buyGame ให้สมบูรณ์
// func buyGame(w http.ResponseWriter, r *http.Request) {
// 	if r.Method != http.MethodPost {
// 		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// 1. อ่านข้อมูล user_id และ game_id จาก request body
// 	var req BuyGameRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
// 		return
// 	}

// 	// 2. เริ่มต้น Transaction
// 	tx, err := db.Begin()
// 	if err != nil {
// 		http.Error(w, `{"error":"Cannot start transaction"}`, http.StatusInternalServerError)
// 		return
// 	}
// 	// ถ้าเกิดข้อผิดพลาด ให้ Rollback ทั้งหมด
// 	defer tx.Rollback()

// 	// 3. ✅ แก้ไข: ดึงข้อมูล "ราคาเกม" และ "เงินในกระเป๋า" แยกกันเพื่อความถูกต้อง
// 	var gamePrice float64
// 	var userCash float64
// 	var wid int

// 	// ดึงราคาเกม
// 	err = tx.QueryRow("SELECT price FROM game WHERE game_id = ?", req.GameID).Scan(&gamePrice)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			http.Error(w, `{"error":"Game not found"}`, http.StatusNotFound)
// 			return
// 		}
// 		http.Error(w, `{"error":"Database error fetching game price"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// ดึงเงินในกระเป๋าและ wallet ID
// 	err = tx.QueryRow("SELECT cash, wid FROM wallet WHERE user_id = ?", req.UserID).Scan(&userCash, &wid)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			http.Error(w, `{"error":"User wallet not found"}`, http.StatusNotFound)
// 			return
// 		}
// 		http.Error(w, `{"error":"Database error fetching wallet info"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 4. ตรวจสอบว่ามีเงินพอหรือไม่
// 	if userCash < gamePrice {
// 		http.Error(w, `{"error":"Insufficient funds"}`, http.StatusPaymentRequired) // 402 Payment Required
// 		return
// 	}

// 	// 5. หักเงินออกจาก Wallet ของผู้ใช้
// 	_, err = tx.Exec("UPDATE wallet SET cash = cash - ? WHERE user_id = ?", gamePrice, req.UserID)
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to deduct funds from wallet"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 6. สร้าง Order ใหม่ในตาราง `orders`
// 	orderRes, err := tx.Exec("INSERT INTO orders (user_id, total_amount, order_date) VALUES (?, ?, NOW())", req.UserID, gamePrice)
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to create order"}`, http.StatusInternalServerError)
// 		return
// 	}
// 	newOrderID, err := orderRes.LastInsertId()
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to get new order ID"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 7. เพิ่มรายละเอียด Order ลงในตาราง `order_details`
// 	_, err = tx.Exec("INSERT INTO order_details (order_id, game_id, price) VALUES (?, ?, ?)", newOrderID, req.GameID, gamePrice)
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to create order detail"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 8. อัปเดตยอดขาย ('sold') ในตาราง 'game'
// 	_, err = tx.Exec("UPDATE game SET sold = sold + 1 WHERE game_id = ?", req.GameID)
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to update game sold count"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 9. เพิ่มประวัติการใช้เงิน (ติดลบ) ลงใน `historywallet`
// 	currentDate := time.Now().Format("2006-01-02 15:04:05")
// 	_, err = tx.Exec("INSERT INTO historywallet (date, amount, wid) VALUES (?, ?, ?)", currentDate, -gamePrice, wid)
// 	if err != nil {
// 		http.Error(w, `{"error":"Failed to insert into wallet history"}`, http.StatusInternalServerError)
// 		return
// 	}

// 	// 10. ถ้าทุกอย่างสำเร็จทั้งหมด ให้ Commit Transaction
// 	if err := tx.Commit(); err != nil {
// 		http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
// 		return
// 	}

//		// 11. ส่ง Response สำเร็จกลับไป
//		w.Header().Set("Content-Type", "application/json")
//		w.WriteHeader(http.StatusOK)
//		json.NewEncoder(w).Encode(map[string]interface{}{
//			"message":     "Purchase successful!",
//			"order_id":    newOrderID,
//			"game_id":     req.GameID,
//			"paid_amount": gamePrice,
//		})
//	}
func buyGame(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// 1. อ่านข้อมูล user_id และ game_id จาก request body
	var req BuyGameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// 2. เริ่มต้น Transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, `{"error":"Cannot start transaction"}`, http.StatusInternalServerError)
		return
	}
	// ถ้าเกิดข้อผิดพลาด ให้ Rollback ทั้งหมด
	defer tx.Rollback()

	// 3. ✅ แก้ไข: ดึงข้อมูล "ราคาเกม" และ "เงินในกระเป๋า" แยกกันเพื่อความถูกต้อง
	var gamePrice float64
	var userCash float64
	var wid int

	// ดึงราคาเกม
	err = tx.QueryRow("SELECT price FROM game WHERE game_id = ?", req.GameID).Scan(&gamePrice)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"Game not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Database error fetching game price"}`, http.StatusInternalServerError)
		return
	}

	// ✅ การเปลี่ยนแปลงที่สำคัญ: เพิ่ม FOR UPDATE เพื่อล็อคแถวข้อมูล Wallet
	// ดึงเงินในกระเป๋าและ wallet ID พร้อมกับ "ล็อค" แถวข้อมูลนี้ทันที
	// Transaction อื่นจะไม่สามารถเข้ามาอ่านหรือแก้ไขข้อมูล Wallet ของ user คนนี้ได้จนกว่า Transaction ปัจจุบันจะเสร็จสิ้น
	err = tx.QueryRow("SELECT cash, wid FROM wallet WHERE user_id = ? FOR UPDATE", req.UserID).Scan(&userCash, &wid)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error":"User wallet not found"}`, http.StatusNotFound)
			return
		}
		http.Error(w, `{"error":"Database error fetching wallet info"}`, http.StatusInternalServerError)
		return
	}

	// 4. ตรวจสอบว่ามีเงินพอหรือไม่
	if userCash < gamePrice {
		http.Error(w, `{"error":"Insufficient funds"}`, http.StatusPaymentRequired) // 402 Payment Required
		return
	}

	// 5. หักเงินออกจาก Wallet ของผู้ใช้
	_, err = tx.Exec("UPDATE wallet SET cash = cash - ? WHERE user_id = ?", gamePrice, req.UserID)
	if err != nil {
		http.Error(w, `{"error":"Failed to deduct funds from wallet"}`, http.StatusInternalServerError)
		return
	}

	// 6. สร้าง Order ใหม่ในตาราง `orders`
	orderRes, err := tx.Exec("INSERT INTO orders (user_id, total_amount, order_date) VALUES (?, ?, NOW())", req.UserID, gamePrice)
	if err != nil {
		http.Error(w, `{"error":"Failed to create order"}`, http.StatusInternalServerError)
		return
	}
	newOrderID, err := orderRes.LastInsertId()
	if err != nil {
		http.Error(w, `{"error":"Failed to get new order ID"}`, http.StatusInternalServerError)
		return
	}

	// 7. เพิ่มรายละเอียด Order ลงในตาราง `order_details`
	_, err = tx.Exec("INSERT INTO order_details (order_id, game_id, price) VALUES (?, ?, ?)", newOrderID, req.GameID, gamePrice)
	if err != nil {
		http.Error(w, `{"error":"Failed to create order detail"}`, http.StatusInternalServerError)
		return
	}

	// 8. อัปเดตยอดขาย ('sold') ในตาราง 'game'
	_, err = tx.Exec("UPDATE game SET sold = sold + 1 WHERE game_id = ?", req.GameID)
	if err != nil {
		http.Error(w, `{"error":"Failed to update game sold count"}`, http.StatusInternalServerError)
		return
	}

	// 9. เพิ่มประวัติการใช้เงิน (ติดลบ) ลงใน `historywallet`
	currentDate := time.Now().Format("2006-01-02 15:04:05")
	_, err = tx.Exec("INSERT INTO historywallet (date, amount, wid) VALUES (?, ?, ?)", currentDate, -gamePrice, wid)
	if err != nil {
		http.Error(w, `{"error":"Failed to insert into wallet history"}`, http.StatusInternalServerError)
		return
	}

	// 10. ถ้าทุกอย่างสำเร็จทั้งหมด ให้ Commit Transaction
	if err := tx.Commit(); err != nil {
		http.Error(w, `{"error":"Failed to commit transaction"}`, http.StatusInternalServerError)
		return
	}

	// 11. ส่ง Response สำเร็จกลับไป
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Purchase successful!",
		"order_id":    newOrderID,
		"game_id":     req.GameID,
		"paid_amount": gamePrice,
	})
}

///////////////////////////////////////////////////////////////

// handler สำหรับค้นหาเกมโดยเฉพาะ
func searchGames(w http.ResponseWriter, r *http.Request) {
	// 1. ดึงค่า search (ชื่อเกม) และ type_name (ชื่อประเภท) จาก URL
	searchTerm := r.URL.Query().Get("search")
	typeName := r.URL.Query().Get("type_name") // 👈 เปลี่ยนจาก type_id

	// 2. สร้างคำสั่ง SQL พื้นฐาน และ slice สำหรับเก็บค่า
	query := "SELECT g.game_id, g.game_name, g.price, g.image, g.description, g.release_date, g.sold, g.type_id, g.user_id FROM game g"
	joinClause := ""
	args := []interface{}{}
	whereClauses := []string{}

	// 3. เพิ่มเงื่อนไขการค้นหาจาก "ชื่อเกม" (เหมือนเดิม)
	if searchTerm != "" {
		whereClauses = append(whereClauses, "g.game_name LIKE ?")
		args = append(args, "%"+searchTerm+"%")
	}

	// 4. ✅ เพิ่มเงื่อนไขการค้นหาจาก "ชื่อประเภท"
	if typeName != "" {
		// ถ้ามีการค้นหาจากประเภท ต้อง JOIN ตาราง typegame เข้ามา
		joinClause = " JOIN typegame t ON g.type_id = t.type_id"
		whereClauses = append(whereClauses, "t.type_name = ?") // 👈 ค้นหาจาก t.type_name
		args = append(args, typeName)
	}

	// 5. นำ JOIN และ WHERE มารวมกับคำสั่งหลัก
	query += joinClause
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Game{})
		return
	}

	// 6. Execute SQL (เหมือนเดิม)
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// ... ส่วนแปลงข้อมูลเป็น JSON เหมือนกับฟังก์ชัน getGames ...
	var games []Game
	for rows.Next() {
		var g Game
		if err := rows.Scan(&g.GameID, &g.GameName, &g.Price, &g.Image, &g.Description, &g.ReleaseDate, &g.Sold, &g.TypeID, &g.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		games = append(games, g)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(games)
}

type LibraryGame struct {
	GameID   int     `json:"game_id"`
	GameName string  `json:"game_name"`
	Image    *string `json:"image"`
}

func getUserLibraryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, `{"error":"Query parameter 'user_id' is required"}`, http.StatusBadRequest)
		return
	}

	// ใช้ SQL JOIN เพื่อดึงรายชื่อเกมที่ไม่ซ้ำกัน
	query := `
		SELECT DISTINCT
			g.game_id,
			g.game_name,
			g.image
		FROM orders o
		JOIN order_details od ON o.order_id = od.order_id
		JOIN game g ON od.game_id = g.game_id
		WHERE o.user_id = ?
		ORDER BY g.game_name ASC
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		http.Error(w, `{"error":"Database query error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var library []LibraryGame
	for rows.Next() {
		var item LibraryGame
		if err := rows.Scan(&item.GameID, &item.GameName, &item.Image); err != nil {
			http.Error(w, `{"error":"Failed to scan row"}`, http.StatusInternalServerError)
			return
		}
		library = append(library, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(library)
}
