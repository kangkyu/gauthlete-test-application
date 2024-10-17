package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/kangkyu/gauthlete"
)

var authleteClient *gauthlete.ServiceClient

func main() {
	// Initialize Authlete client
	authleteClient = gauthlete.NewServiceClient()

	// Set up routes
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/token", tokenHandler)
	// http.HandleFunc("/userinfo", userInfoHandler)

	// Start server
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body>
        <h1>Authlete Test App</h1>
        <a href="/authorize">Start OAuth Flow</a>
    </body></html>`)
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Find parameter from `r`
	values := r.URL.Query()
	parameters := values.Encode()

	response, err := authleteClient.Authorization(parameters)
	if err != nil {
		http.Error(w, "Authorization endpoint errored: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch response.Action {
	case "INTERACTION":
		// Find ticket from `response`
		ticket := response.Ticket

		// TODO: not 'Jimmy', what should it be?
		// The subject (= a user account managed by the service) who has granted authorization to the client application.
		issueResp, err := authleteClient.AuthorizationIssue(ticket, "Jimmy")
		if err != nil {
			http.Error(w, "Authorization issue endpoint errored: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Find code from `issueResp.ResponseContent`
		content := issueResp.ResponseContent

		http.Redirect(w, r, content, http.StatusFound)

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
