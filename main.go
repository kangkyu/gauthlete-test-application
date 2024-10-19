package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/postgresstore"
	"github.com/alexedwards/scs/v2"
	"github.com/kangkyu/gauthlete"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	authleteClient *gauthlete.ServiceClient
	db             *sql.DB

	dbOnce     sync.Once
	clientOnce sync.Once

	sessionManager *scs.SessionManager
)

func initDB() {
	dbOnce.Do(func() {
		var err error
		db, err = sql.Open("postgres", "postgresql://tester:password@localhost/test_application_development?sslmode=disable")
		if err != nil {
			log.Fatalf("Error opening database connection: %v", err)
		}

		err = db.Ping()
		if err != nil {
			log.Fatalf("Error connecting to the database: %v", err)
		}

		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(25)
		db.SetConnMaxLifetime(5 * time.Minute)

		log.Println("Database connection initialized")
	})
}

func initAuthleteClient() {
	clientOnce.Do(func() {
		authleteClient = gauthlete.NewServiceClient()
		log.Println("Authlete client initialized")
	})
}

func initSessionManager() {
	sessionManager = scs.New()
	sessionManager.Store = postgresstore.New(db)
	sessionManager.Lifetime = 12 * time.Hour
	sessionManager.Cookie.Secure = true
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func main() {
	// Initialize database and Authlete client
	initDB()
	initAuthleteClient()
	initSessionManager()

	// Set up routes
	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/userinfo", userInfoHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/signup", signupHandler)

	// Start server
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", sessionManager.LoadAndSave(mux)))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body>
        <h1>Authlete Test App</h1>
    </body></html>`)
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// 1) Find parameter from `r`
	values := r.URL.Query()
	parameters := values.Encode()

	response, err := authleteClient.Authorization(parameters)
	if err != nil {
		http.Error(w, "Authorization endpoint errored: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch response.Action {
	case "INTERACTION":
		// 2) Find ticket from `response`
		ticket := response.Ticket

		// Store the Authlete ticket and state in the session
		sessionManager.Put(r.Context(), "authorizationTicket", ticket)

		// Redirect to login
		http.Redirect(w, r, "/login", http.StatusFound)

	case "BAD_REQUEST":
		http.Error(w, "Bad request: "+response.ResultMessage, http.StatusBadRequest)

	case "UNAUTHORIZED":
		http.Error(w, "Unauthorized: "+response.ResultMessage, http.StatusUnauthorized)

	default:
		http.Error(w, "Unexpected response from authorization server", http.StatusInternalServerError)
	}
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Check for client credentials in form body
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	r.Form.Del("client_id")
	r.Form.Del("client_secret")

	// Extract parameters
	parameters := r.Form.Encode()

	// Call Authlete's /api/auth/token API
	client := gauthlete.NewServiceClient()
	tokenResponse, err := client.Token(parameters, clientID, clientSecret)
	if err != nil {
		http.Error(w, "Token request failed", http.StatusInternalServerError)
		return
	}

	// Handle the response
	switch tokenResponse.Action {
	case "INTERNAL_SERVER_ERROR":
		http.Error(w, tokenResponse.ResultMessage, http.StatusInternalServerError)
	case "BAD_REQUEST":
		http.Error(w, tokenResponse.ResultMessage, http.StatusBadRequest)
	case "OK":
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token":  tokenResponse.AccessToken,
			"token_type":    tokenResponse.TokenType,
			"expires_in":    tokenResponse.ExpiresIn,
			"refresh_token": tokenResponse.RefreshToken,
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to generate response", http.StatusInternalServerError)
			return
		}

		w.Write(jsonResponse)
	default:
		http.Error(w, "Unexpected response from token endpoint", http.StatusInternalServerError)
	}
}

func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
	if bearerToken == authHeader {
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	introspectionResponse, err := authleteClient.TokenIntrospect(bearerToken)
	if err != nil {
		http.Error(w, "Token introspection failed", http.StatusInternalServerError)
		return
	}

	if !introspectionResponse.Usable {
		http.Error(w, "Token is not active", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.Atoi(introspectionResponse.Subject)
	if err != nil {
		http.Error(w, "Failed to parse user id: "+err.Error(), http.StatusInternalServerError)
		return
	}
	user, err := getUser(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sub":      user.ID,
		"username": user.Username,
	})
}

func authenticateUser(username, password string) (int, error) {
	var id int
	var hashedPassword []byte
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = $1", username).Scan(&id, &hashedPassword)
	if err != nil {
		return 0, err
	}

	// In a real app, you'd compare hashed passwords here
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return 0, fmt.Errorf("invalid password")
	}

	return id, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Display login form
		fmt.Fprintf(w, `<html><body>
		<form method="post">
			Username: <input type="text" name="username"><br>
			Password: <input type="password" name="password"><br>
			<input type="submit" value="Login">
		</form>
		New user? <a href='/signup'>Sign Up</a>
		</body></html>`)
		return
	}
	// Retrieve the session data
	authleteTicket := sessionManager.GetString(r.Context(), "authorizationTicket")

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Authenticate user
		userID, err := authenticateUser(username, password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Issue the authorization
		issueResp, err := authleteClient.AuthorizationIssue(authleteTicket, fmt.Sprintf("%d", userID))
		if err != nil {
			http.Error(w, "Authorization issue endpoint errored: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Clear the session
		sessionManager.Remove(r.Context(), "authorizationTicket")

		// 3) Find code from `issueResp.ResponseContent`
		content := issueResp.ResponseContent

		http.Redirect(w, r, content, http.StatusFound)
	}
}

func idExists(id int) (bool, error) {
	var exists bool
	stmt := "SELECT EXISTS(SELECT true FROM users WHERE id = $1)"

	err := db.QueryRow(stmt, id).Scan(&exists)
	return exists, err
}

func usernameExists(username string) (bool, error) {
	var exists bool
	stmt := "SELECT EXISTS(SELECT true FROM users WHERE username = $1)"

	err := db.QueryRow(stmt, username).Scan(&exists)
	return exists, err
}

func getUser(id int) (*User, error) {
	var user User
	stmt := "SELECT id, username FROM users WHERE id = $1"

	err := db.QueryRow(stmt, id).Scan(&user.ID, &user.Username)
	return &user, err
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Display signup form
		fmt.Fprintf(w, `<html><body>
			<h2>Sign Up</h2>
			<form method="post">
				Username: <input type="text" name="username" required><br>
				Password: <input type="password" name="password" required><br>
				<input type="submit" value="Sign Up">
			</form>
		</body></html>`)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Basic input validation
		if username == "" || password == "" {
			http.Error(w, "Username and password are required", http.StatusBadRequest)
			return
		}

		// Check if user already exists
		exists, err := usernameExists(username)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		if exists {
			http.Error(w, "Username already taken", http.StatusConflict)
			return
		}

		err = registerUser(username, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to login page or show success message
		fmt.Fprintf(w, "<html><body>User created successfully. <a href='/login'>Login</a></body></html>")
	}
}

func registerUser(username, password string) error {

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {

		return fmt.Errorf("Error hashing password")
	}

	// Insert new user into the database
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES ($1, $2)", username, hashedPassword)
	if err != nil {
		return fmt.Errorf("Error creating user")
	}

	return nil
}
