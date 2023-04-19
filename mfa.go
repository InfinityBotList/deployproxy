package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/infinitybotlist/eureka/crypto"
	"github.com/pquerna/otp/totp"
)

func loadMfaRoutes(r *chi.Mux) {
	r.Get("/__dp/mfaImages/{hash}", func(w http.ResponseWriter, r *http.Request) {
		// Get image from redis
		img, err := rdb.Get(ctx, "mfaimg:"+chi.URLParam(r, "hash")).Bytes()

		if err != nil {
			http.Error(w, "Internal error when loading MFA image: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "image/png")
		w.Write(img)
	})
}

func setupMfa() {
	_, err := pool.Exec(ctx, "CREATE TABLE IF NOT EXISTS __dp_mfa (user_id TEXT PRIMARY KEY, secret TEXT, domain TEXT NOT NULL, validated BOOL DEFAULT FALSE)")

	if err != nil {
		panic("Failed to create mfa table:" + err.Error())
	}
}

func mfaCreateView(w http.ResponseWriter, r *http.Request, deploy Deploy, rsess RedisSession) {
	// Create new MFA credentials
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DeployProxy",
		AccountName: rsess.UserID,
	})

	if err != nil {
		http.Error(w, "Internal error when generating MFA: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = pool.Exec(ctx, "INSERT INTO __dp_mfa (user_id, secret, domain) VALUES ($1, $2, $3)", rsess.UserID, key.Secret(), deploy.URL)

	if err != nil {
		http.Error(w, "Internal error when creating MFA: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store image on redis
	img, err := key.Image(200, 200)

	// Encode image to PNG
	buf := new(bytes.Buffer)

	png.Encode(buf, img)

	if err != nil {
		http.Error(w, "Internal error when creating MFA image: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tok := crypto.RandString(128)

	qrImgHash := rsess.UserID + "_" + tok

	err = rdb.Set(ctx, "mfaimg:"+qrImgHash, buf.Bytes(), 5*time.Minute).Err()

	if err != nil {
		http.Error(w, "Internal error when storing MFA image: "+err.Error(), http.StatusInternalServerError)
		return
	}

	t, err := template.New("mfa_new").Parse(mfaNewHTML)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error parsing login template"))
		return
	}

	t.Execute(w, MfaNewView{
		Secret: key.Secret(),
		QRCode: deploy.URL + "/__dp/mfaImages/" + qrImgHash,
	})
}

func mfaValidateView(w http.ResponseWriter, r *http.Request, deploy Deploy) {
	t, err := template.New("mfa_validate_html").Parse(mfaValidateHTML)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error parsing login template"))
		return
	}

	t.Execute(w, nil)
}

func mfaView(w http.ResponseWriter, r *http.Request, deploy Deploy) {
	if !deploy.MFA {
		http.Error(w, "Internal error: MFA not enabled for this deploy", http.StatusForbidden)
		return
	}

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

	if time.Since(rsess.CreatedAt) > 5*time.Minute {
		loginView(w, r)
		return
	}

	switch r.Method {
	case "GET":
		// Check if user has a MFA secret
		var count int64

		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM __dp_mfa WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL).Scan(&count)

		if err != nil {
			http.Error(w, "Internal error when checking for MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if count == 0 {
			mfaCreateView(w, r, deploy, rsess)
			return
		}

		// Check if MFA code is validated
		var validated bool

		err = pool.QueryRow(ctx, "SELECT validated FROM __dp_mfa WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL).Scan(&validated)

		if err != nil {
			http.Error(w, "Internal error when checking for MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if !validated {
			// Delete old MFA secret
			_, err = pool.Exec(ctx, "DELETE FROM __dp_mfa WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL)

			if err != nil {
				http.Error(w, "Internal error when deleting MFA: "+err.Error(), http.StatusInternalServerError)
				return
			}

			mfaCreateView(w, r, deploy, rsess)
			return
		}

		mfaValidateView(w, r, deploy)
	case "POST":
		// Check if user has a MFA secret
		var count int64

		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM __dp_mfa WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL).Scan(&count)

		if err != nil {
			http.Error(w, "Internal error when checking for MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if count == 0 {
			mfaCreateView(w, r, deploy, rsess)
			return
		}

		// Get secret
		var secret string

		err = pool.QueryRow(ctx, "SELECT secret FROM __dp_mfa WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL).Scan(&secret)

		if err != nil {
			http.Error(w, "Internal error when checking for MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Get inputted mfa-code from form
		err = r.ParseForm()

		if err != nil {
			http.Error(w, "Internal error when parsing form: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(r.Form)

		mfaCode := r.Form.Get("mfa-code")

		if mfaCode == "" {
			http.Error(w, "No MFA code provided", http.StatusBadRequest)
			return
		}

		// Validate MFA code
		valid := totp.Validate(mfaCode, secret)

		if !valid {
			http.Error(w, "MFA code is invalid: "+mfaCode, http.StatusBadRequest)
			return
		}

		// Set MFA as validated
		_, err = pool.Exec(ctx, "UPDATE __dp_mfa SET validated = true WHERE user_id = $1 AND domain = $2", rsess.UserID, deploy.URL)

		if err != nil {
			http.Error(w, "Internal error when validating MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Validate session
		rsess.MFA = true

		sessBytes, err := json.Marshal(rsess)

		if err != nil {
			http.Error(w, "Internal error when validating MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		err = rdb.Set(ctx, cookie.Value, sessBytes, 2*time.Hour).Err()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error creating session"))
			return
		}

		// Redirect to original URL
		if r.Form.Get("js") == "" {
			state := r.URL.Query().Get("state")

			// Try to hexdecode state if not empty
			url := ""

			if state != "" {
				urlBytes, err := hex.DecodeString(state)

				if err == nil {
					url = string(urlBytes)
				}
			}

			// Redirect to state
			http.Redirect(w, r, deploy.URL+url, http.StatusFound)
		}
	}
}
