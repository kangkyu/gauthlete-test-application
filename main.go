package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/kangkyu/gauthlete" // Import your Authlete library
)

var authleteClient *gauthlete.ServiceClient

func main() {
    // Initialize Authlete client
    authleteClient = gauthlete.NewServiceClient()

    // Set up routes
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/authorize", authorizeHandler)
    http.HandleFunc("/callback", callbackHandler)
    http.HandleFunc("/introspect", introspectHandler)

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
    // Implement authorization request using your Authlete library
    // This is where you'd call authleteClient.Authorization()
    // For now, we'll just redirect to the callback with a dummy code
    http.Redirect(w, r, "/callback?code=dummy_auth_code", http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    // Here you'd exchange the code for a token using your Authlete library
    // For now, we'll just display the code
    fmt.Fprintf(w, "Received authorization code: %s", code)
}

func introspectHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    if token == "" {
        http.Error(w, "Token is required", http.StatusBadRequest)
        return
    }

    resp, err := authleteClient.TokenIntrospect(token)
    if err != nil {
        http.Error(w, "Error introspecting token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "Token active: %v", resp.Active)
    // Display other introspection response fields as needed
}
