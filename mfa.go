package main

import (
	"bytes"
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
	r.Get("/_dp/mfaImages/{hash}", func(w http.ResponseWriter, r *http.Request) {
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
		QRCode: deploy.URL + "/_dp/mfaImages/" + qrImgHash,
	})

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

		err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM __dp_mfa WHERE user_id = $1", rsess.UserID).Scan(&count)

		if err != nil {
			http.Error(w, "Internal error when checking for MFA: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if count == 0 {
			mfaCreateView(w, r, deploy, rsess)
			return
		}
	}
}
