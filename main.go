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

	"golang.org/x/exp/slices"
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

const (
	sessCookieName = "__dpsession"
	extCookieName  = "__dpext"
	expiryTime     = 300
)

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
	var allowedHeaders = []string{
		"Content-Type",
		"Content-Encoding",
		"Content-Security-Policy",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Allow-Credentials",
		"Access-Control-Max-Age",
		"Access-Control-Expose-Headers",
		"Access-Control-Request-Headers",
		"Access-Control-Request-Method",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
	}

	// Proxy request to To

	// Special case optimization for OPTIONS requests, no need to send/read the body
	if r.Method == "OPTIONS" {
		// Fetch request, no body should be sent
		cli := &http.Client{
			Timeout: 2 * time.Minute,
		}

		url := deploy.To + r.URL.Path

		if r.URL.RawQuery != "" {
			url += "?" + r.URL.RawQuery
		}

		req, err := http.NewRequest(r.Method, deploy.To+r.URL.Path+"?"+r.URL.RawQuery, nil)

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

		for k, v := range resp.Header {
			if slices.Contains(allowedHeaders, k) {
				w.Header()[k] = v
			}
		}

		w.WriteHeader(resp.StatusCode)
		return
	}

	cli := &http.Client{
		Timeout: 2 * time.Minute,
	}

	url := deploy.To + r.URL.Path

	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
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
		if slices.Contains(allowedHeaders, k) {
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

	// Serve common CSS
	r.HandleFunc("/__dp/common-css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte(commonCSS))
	})

	r.HandleFunc("/__dp/logout", func(w http.ResponseWriter, r *http.Request) {
		// Get session cookie
		sessionCookie, err := r.Cookie(sessCookieName)

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
			Name:     sessCookieName,
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			SameSite: http.SameSiteLaxMode, // We want them to be sent to APIs etc
			Secure:   true,
			HttpOnly: true,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     extCookieName,
			Value:    "",
			Expires:  time.Now().Add(-1 * time.Hour),
			SameSite: http.SameSiteNoneMode, // We want them to be sent to APIs etc
			Secure:   true,
			HttpOnly: true,
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
		sessionCookie, err := r.Cookie(sessCookieName)

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
			Name:     sessCookieName,
			Value:    sessId,
			Expires:  time.Now().Add(2 * time.Hour),
			SameSite: http.SameSiteLaxMode,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
		})

		// Create cookie for external API's
		extId := crypto.RandString(256)

		err = rdb.Set(ctx, extId, sessId, 2*time.Hour).Err()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error creating session"))
			return
		}

		// Get root domain for cookie
		rootDomain := strings.Split(r.Host, ".")

		if len(rootDomain) > 2 {
			// Get last two parts of domain
			rootDomain = rootDomain[len(rootDomain)-2:]
		}

		http.SetCookie(w, &http.Cookie{
			Name:     extCookieName,
			Value:    extId,
			Expires:  time.Now().Add(2 * time.Hour),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: false,
			Domain:   strings.Join(rootDomain, "."),
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

		if deploy.API != nil {
			// Get corresponding deploy
			correspondingDeploy, ok := config.Deploys[deploy.API.CorrespondingDeploy]

			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("Corresponding deploy not found: " + deploy.API.CorrespondingDeploy))
				return
			}

			w.Header().Add("Access-Control-Allow-Origin", correspondingDeploy.URL)
			w.Header().Add("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Access-Control-Allow-Headers", strings.Join(deploy.API.AllowHeaders, ", "))
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")

			// OPTIONS requests are unauthenticated/we dont care
			if r.Method == "OPTIONS" {
				proxy(w, r, deploy)
				return
			}

			// Check if in bypass
			if deploy.API.Bypass != nil {
				for _, bypass := range deploy.API.Bypass.EndsWith {
					if strings.HasSuffix(r.URL.Path, bypass) {
						proxy(w, r, deploy)
						return
					}
				}
			}

			// Check for external cookie
			if cookie, err := r.Cookie(extCookieName); err == nil {
				// Get session id from redis
				sessId, err := rdb.Get(ctx, cookie.Value).Result()

				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("{\"message\":\"Please refresh the page. Session for protected deploy expired\",\"error\":true}"))
					return
				}

				// Get session from redis
				sessBytes, err := rdb.Get(ctx, sessId).Result()

				if err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("{\"message\":\"Please refresh the page. Session for protected deploy invalid\",\"error\":true}"))
					return
				}

				var rsess RedisSession

				err = json.Unmarshal([]byte(sessBytes), &rsess)

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("{\"message\":\"Error unmarshalling deployproxy session\",\"error\":true}"))
					return
				}

				if rsess.DeployURL != correspondingDeploy.URL {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("{\"message\":\"deployproxy DeployURL mismatch\",\"error\":true}"))
					return
				}

				if rsess.IP != r.RemoteAddr {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("{\"message\":\"deployproxy IP mismatch\",\"error\":true}"))
					return
				}

				// Check if user is in database
				var userID string

				err = pool.QueryRow(ctx, "SELECT user_id FROM users WHERE user_id = $1", rsess.UserID).Scan(&userID)

				if err != nil {
					if err == pgx.ErrNoRows {
						w.WriteHeader(http.StatusUnauthorized)
						w.Write([]byte("{\"message\":\"deployproxy: failed to find user\",\"error\":true}"))
						return
					}

					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("{\"message\":\"deployproxy: error checking if user exists\",\"error\":true}"))
					return
				}

				if time.Now().Unix()-rsess.LastChecked > expiryTime {
					// Check perms
					if err := checkPerms(rsess.UserID, correspondingDeploy.Perms); err != nil {
						w.WriteHeader(http.StatusUnauthorized)
						var errStruct struct {
							Message string `json:"message"`
							Error   bool   `json:"error"`
						}

						errStruct.Message = err.Error()
						errStruct.Error = true

						errBytes, err := json.Marshal(errStruct)

						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							w.Write([]byte("{\"message\":\"deployproxy: failed to check perms\",\"error\":true}"))
							return
						}

						w.Write(errBytes)
						return
					}
					rsess.LastChecked = time.Now().Unix()

					sessBytes, err := json.Marshal(rsess)

					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("{\"message\":\"deployproxy: failed to marshal session\",\"error\":true}}"))
						return
					}

					// Set session in redis
					err = rdb.SetArgs(ctx, sessId, sessBytes, redis.SetArgs{
						KeepTTL: true,
					}).Err()

					if err != nil {
						w.WriteHeader(http.StatusInternalServerError)
						w.Write([]byte("{\"message\":\"deployproxy: failed to set session in redis\",\"error\":true}"))
						return
					}
				}

				proxy(w, r, deploy)
				return
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("{\"message\":\"Please refresh the page. No extCookie found\",\"error\":true}"))
				return
			}
		}

		if strings.HasPrefix(r.URL.Path, "/_next/image") || r.URL.Path == "/favicon.ico" || r.URL.Path == "/manifest.json" || r.URL.Path == "/robots.txt" {
			proxy(w, r, deploy)
		}

		// Check for cookie named __dpsession
		if _, err := r.Cookie(sessCookieName); err != nil {
			// If cookie doesn't exist, redirect to login page
			loginView(w, r)
			return
		} else {
			// If cookie exists, check if it's valid
			cookie, err := r.Cookie(sessCookieName)

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

			// Ensure extCookie also exsts
			if _, err := r.Cookie(extCookieName); err != nil {
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

			if time.Now().Unix()-rsess.LastChecked > expiryTime {
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
