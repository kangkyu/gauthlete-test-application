package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"html/template"
	"net/http"
	"path/filepath"
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

	// Static file serving
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Route handlers
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
    tmpl := template.Must(template.ParseFiles(filepath.Join("templates", "home.html")))

    err := tmpl.Execute(w, nil)
    if err != nil {
        http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
        return
    }
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

// LoginData holds the data to be passed to the template
type LoginData struct {
	Error string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the template once at init or use a template cache
	tmpl := template.Must(template.ParseFiles(filepath.Join("templates", "login.html")))

	if r.Method == "GET" {
		// Display login form
		err := tmpl.Execute(w, nil)
		if err != nil {
			http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == "POST" {
		// Retrieve the session data
		authleteTicket := sessionManager.GetString(r.Context(), "authorizationTicket")
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Authenticate user
		userID, err := authenticateUser(username, password)
		if err != nil {
			// Show error in the template
			data := LoginData{
				Error: "Invalid username or password",
			}
			tmpl.Execute(w, data)
			return
		}

		// Issue the authorization
		issueResp, err := authleteClient.AuthorizationIssue(authleteTicket, fmt.Sprintf("%d", userID))
		if err != nil {
			data := LoginData{
				Error: "Authorization failed. Please try again.",
			}
			tmpl.Execute(w, data)
			return
		}

		// Clear the session
		sessionManager.Remove(r.Context(), "authorizationTicket")

		// Redirect to the response content
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

type SignupData struct {
    Username string
    Error    string
    Success  string
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles(filepath.Join("templates", "signup.html")))

    if r.Method == "GET" {
        err := tmpl.Execute(w, nil)
        if err != nil {
            http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
            return
        }
        return
    }

    if r.Method == "POST" {
        username := r.FormValue("username")
        password := r.FormValue("password")
        data := SignupData{
            Username: username,
        }

        // Basic input validation
        if username == "" || password == "" {
            data.Error = "Username and password are required"
            tmpl.Execute(w, data)
            return
        }

        // Password length validation
        if len(password) < 8 {
            data.Error = "Password must be at least 8 characters long"
            tmpl.Execute(w, data)
            return
        }

        // Check if user already exists
        exists, err := usernameExists(username)
        if err != nil {
            data.Error = "An error occurred. Please try again"
            tmpl.Execute(w, data)
            return
        }
        if exists {
            data.Error = "Username already taken"
            tmpl.Execute(w, data)
            return
        }

        // Register the user
        err = registerUser(username, password)
        if err != nil {
            data.Error = "Failed to create account. Please try again"
            tmpl.Execute(w, data)
            return
        }

        // Show success message
        data.Success = "Account created successfully!"
        tmpl.Execute(w, data)
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
