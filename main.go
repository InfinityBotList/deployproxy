package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	"gopkg.in/yaml.v3"

	"github.com/bwmarrin/discordgo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/infinitybotlist/eureka/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var (
	config  Config
	secrets Secrets
	pool    *pgxpool.Pool
	ctx     = context.Background()
	rdb     *redis.Client
	discord *discordgo.Session
)

//go:embed login.html
var loginHTML string

//go:embed down.html
var downHTML string

func loginView(w http.ResponseWriter, r *http.Request) {
	deploy, ok := config.Deploys[r.Host]

	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Deploy to protect not found: " + r.Host))
		return
	}

	t, err := template.New("login").Parse(loginHTML)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error parsing login template"))
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	t.Execute(w, LoginView{
		Deploy:     deploy,
		CurrentURL: r.URL.Path,
	})
}

func downView(w http.ResponseWriter, r *http.Request, reason string) {
	t, err := template.New("down").Parse(downHTML)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error parsing down template"))
		return
	}

	w.WriteHeader(http.StatusRequestTimeout)
	t.Execute(w, Down{
		Error: reason,
	})
}

func proxy(w http.ResponseWriter, r *http.Request, deploy Deploy) {
	// Proxy request to To

	cli := &http.Client{
		Timeout: 2 * time.Minute,
	}

	url := deploy.To + r.URL.Path

	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery + "&v=21"
	} else {
		url += "?v=21"
	}

	req, err := http.NewRequest(r.Method, deploy.To+r.URL.Path+"?"+r.URL.RawQuery, r.Body)

	if err != nil {
		downView(w, r, "Error creating request to backend")
		return
	}

	req.Header = r.Header

	resp, err := cli.Do(req)

	if err != nil {
		downView(w, r, "Error sending request to backend")
		return
	}

	defer resp.Body.Close()

	for k, v := range resp.Header {
		if k == "Content-Type" || k == "Content-Encoding" || k == "Content-Security-Policy" {
			w.Header()[k] = v
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)

	if err != nil {
		downView(w, r, "Error reading response body from backend")
		return
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(bodyBytes)
}

func checkPerms(userId string, perms []Perm) error {
	for _, permNeeded := range perms {
		switch permNeeded {
		case PermAdmin:
			var admin bool

			err := pool.QueryRow(ctx, "SELECT admin FROM users WHERE user_id = $1", userId).Scan(&admin)

			if err != nil {
				if err == pgx.ErrNoRows {
					return errors.New("you are not a IBL user")
				}

				return errors.New("error checking user")
			}

			if !admin {
				return errors.New("user is not an admin")
			}
		}
	}

	return nil
}

func main() {
	// Load config.yaml into Config struct
	file, err := os.Open("config.yaml")

	if err != nil {
		panic(err)
	}

	defer file.Close()

	decoder := yaml.NewDecoder(file)

	err = decoder.Decode(&config)

	if err != nil {
		panic(err)
	}

	// Load secrets.yaml into Secrets struct
	file, err = os.Open("secrets.yaml")

	if err != nil {
		panic(err)
	}

	defer file.Close()

	decoder = yaml.NewDecoder(file)

	err = decoder.Decode(&secrets)

	if err != nil {
		panic(err)
	}

	// Connect to postgres
	pool, err = pgxpool.New(ctx, secrets.DatabaseURL)

	if err != nil {
		panic(err)
	}

	// Connect to redis
	rOptions, err := redis.ParseURL(secrets.RedisURL)

	if err != nil {
		panic(err)
	}

	rdb = redis.NewClient(rOptions)

	// Connect to discord, no intents though
	discord, err = discordgo.New("Bot " + secrets.BotToken)

	if err != nil {
		panic(err)
	}

	// Create wildcard route
	r := chi.NewRouter()

	// A good base middleware stack
	r.Use(
		middleware.Recoverer,
		middleware.RealIP,
		middleware.CleanPath,
		middleware.Logger,
		middleware.Timeout(30*time.Second),
	)

	// For github etc.
	DeployRoutes(r)

	r.HandleFunc("/__dp/logout", func(w http.ResponseWriter, r *http.Request) {
		// Get session cookie
		sessionCookie, err := r.Cookie("__session")

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("No session cookie provided"))
			return
		}

		// Get session from redis
		_, err = rdb.Get(ctx, sessionCookie.Value).Result()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error getting session from redis"))
			return
		}

		// Delete session from redis
		err = rdb.Del(ctx, sessionCookie.Value).Err()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error deleting session from redis"))
			return
		}

		// Delete session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "__session",
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			SameSite: http.SameSiteLaxMode,
		})

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Logged out"))
	})

	r.HandleFunc("/__dp/login", func(w http.ResponseWriter, r *http.Request) {
		deploy, ok := config.Deploys[r.Host]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Deploy to protect not found: " + r.Host))
			return
		}

		// Redirect to oauth2 page
		http.Redirect(w, r, "https://discord.com/api/oauth2/authorize?client_id="+secrets.ClientID+"&redirect_uri="+deploy.URL+"/__dp/confirm&scope=identify&response_type=code&state="+r.URL.Query().Get("url"), http.StatusFound)
	})

	r.HandleFunc("/__dp/sesscookie", func(w http.ResponseWriter, r *http.Request) {
		// Get session cookie
		sessionCookie, err := r.Cookie("__session")

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("No session cookie provided"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sessionCookie.Value))
	})

	r.HandleFunc("/__dp/confirm", func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr == "" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error getting remote address"))
			return
		}

		deploy, ok := config.Deploys[r.Host]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Deploy to protect not found: " + r.Host))
			return
		}

		// Get code from query
		code := r.URL.Query().Get("code")

		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("No code provided"))
			return
		}

		// Get access token from discord
		var token struct {
			AccessToken string `json:"access_token"`
		}

		cli := &http.Client{
			Timeout: 10 * time.Second,
		}

		resp, err := cli.PostForm("https://discord.com/api/v10/oauth2/token", map[string][]string{
			"client_id":     {secrets.ClientID},
			"client_secret": {secrets.ClientSecret},
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {deploy.URL + "/__dp/confirm"},
			"scope":         {"identify"},
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error sending access token request to Discord"))
			return
		}

		if resp.StatusCode != http.StatusOK {
			// Read body
			body, err := io.ReadAll(resp.Body)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error reading body from Discord"))
				return
			}

			fmt.Println(string(body))

			w.WriteHeader(resp.StatusCode)
			w.Write([]byte("Error getting access token from Discord"))
			return
		}

		defer resp.Body.Close()

		err = json.NewDecoder(resp.Body).Decode(&token)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error decoding response from discord"))
			return
		}

		// Get user from discord
		var user struct {
			ID string `json:"id"`
		}

		req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)

		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error creating request to Discord"))
			return
		}

		req.Header.Set("Authorization", "Bearer "+token.AccessToken)

		resp, err = cli.Do(req)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error sending user request to Discord"))
			return
		}

		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(resp.StatusCode)
			w.Write([]byte("Error getting user from Discord"))
			return
		}

		defer resp.Body.Close()

		err = json.NewDecoder(resp.Body).Decode(&user)

		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error decoding user from Discord"))
			return
		}

		// Check user with postgres
		if err := checkPerms(user.ID, deploy.Perms); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		// Create a session
		sess := RedisSession{
			UserID:    user.ID,
			DeployURL: deploy.URL,
			IP:        r.RemoteAddr,
		}

		sessBytes, err := json.Marshal(sess)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error marshalling session"))
			return
		}

		// Set session in redis
		var sessId = crypto.RandString(256)

		err = rdb.Set(ctx, sessId, sessBytes, 2*time.Hour).Err()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error creating session"))
			return
		}

		// Set cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "__session",
			Value:    sessId,
			Expires:  time.Now().Add(2 * time.Hour),
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			Path:     "/",
		})

		// Redirect to state
		http.Redirect(w, r, deploy.URL+r.URL.Query().Get("state"), http.StatusFound)
	})

	r.HandleFunc("/*", func(w http.ResponseWriter, r *http.Request) {
		deploy, ok := config.Deploys[r.Host]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Deploy to protect not found: " + r.Host))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/_next/image") || r.URL.Path == "/favicon.ico" || r.URL.Path == "/manifest.json" || r.URL.Path == "/robots.txt" {
			proxy(w, r, deploy)
		}

		// Check for cookie named __session
		if _, err := r.Cookie("__session"); err != nil {
			// If cookie doesn't exist, redirect to login page
			loginView(w, r)
			return
		} else {
			// If cookie exists, check if it's valid
			cookie, err := r.Cookie("__session")

			if err != nil {
				fmt.Println(err)
				loginView(w, r)
				return
			}

			rsessBytes, err := rdb.Get(ctx, cookie.Value).Bytes()

			if err != nil || len(rsessBytes) == 0 {
				fmt.Println(err)
				loginView(w, r)
				return
			}

			var rsess RedisSession

			err = json.Unmarshal(rsessBytes, &rsess)

			if err != nil {
				fmt.Println(err)
				loginView(w, r)
				return
			}

			if rsess.DeployURL != deploy.URL {
				loginView(w, r)
				return
			}

			if rsess.IP != r.RemoteAddr {
				loginView(w, r)
				return
			}

			// Check if user is in database
			var userID string

			err = pool.QueryRow(ctx, "SELECT user_id FROM users WHERE user_id = $1", rsess.UserID).Scan(&userID)

			if err != nil {
				if err == pgx.ErrNoRows {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("You are not a IBL user"))
					return
				}

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error checking user"))
				return
			}

			if time.Now().Unix()-rsess.LastChecked > 300 {
				// Check perms
				if err := checkPerms(rsess.UserID, deploy.Perms); err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(err.Error()))
					return
				}
				rsess.LastChecked = time.Now().Unix()

				sessBytes, err := json.Marshal(rsess)

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error marshalling session"))
					return
				}

				// Set session in redis
				err = rdb.SetArgs(ctx, cookie.Value, sessBytes, redis.SetArgs{
					KeepTTL: true,
				}).Err()

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Error creating session"))
					return
				}
			}

			proxy(w, r, deploy)
		}
	})

	// Create server
	s := &http.Server{
		Addr:    ":1234",
		Handler: r,
	}

	// Start server
	fmt.Println("Starting server on port 1234")
	err = s.ListenAndServe()

	if err != nil {
		panic(err)
	}
}
