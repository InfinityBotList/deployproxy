package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/go-chi/chi/v5"
	"github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var inDeploy = sync.Mutex{}

type autoLogger struct {
	DeployID string
	Error    bool
}

func (a autoLogger) Write(p []byte) (n int, err error) {
	if a.Error {
		addToDeployLog(a.DeployID, "ERROR: "+string(p))
	} else {
		addToDeployLog(a.DeployID, string(p))
	}

	return len(p), nil
}

func addToDeployLog(deployID string, data string) error {
	currLog := rdb.Get(ctx, "deploy_log_"+deployID).Val()

	if currLog == "" {
		currLog = "[]"
	}

	var logs []string

	err := json.Unmarshal([]byte(currLog), &logs)

	if err != nil {
		return err
	}

	logs = append(logs, data)

	newLog, err := json.Marshal(logs)

	if err != nil {
		return err
	}

	rdb.Set(ctx, "deploy_log_"+deployID, newLog, 24*time.Hour)

	return nil
}

func DeployRoutes(r *chi.Mux) {
	r.HandleFunc("/__dp/logs", func(w http.ResponseWriter, r *http.Request) {
		deployId := r.URL.Query().Get("id")

		deploy, ok := config.Deploys[r.Host]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Deploy to protect not found: " + r.Host))
			return
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

			var owner bool

			err = pool.QueryRow(ctx, "SELECT owner FROM users WHERE user_id = $1", rsess.UserID).Scan(&owner)

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

			if !owner {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Only owners can view the deploy logs"))
				return
			}

			// Load in deploy as []string
			currLog := rdb.Get(ctx, "deploy_log_"+deployId).Val()

			if currLog == "" {
				currLog = "[]"
			}

			var logs []string

			err = json.Unmarshal([]byte(currLog), &logs)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error loading logs"))
				return
			}

			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(
				strings.Join(logs, "\n"),
			))
		}
	})

	// Simple deploy script for handling auto-updates
	r.HandleFunc("/__dp/github", func(w http.ResponseWriter, r *http.Request) {
		if secrets.GithubWebhookSig == "" {
			w.WriteHeader(401)
			w.Write([]byte("This feature is currently disabled, please set the webhook secret github_webhook_sig in secrets.yaml"))
			return
		}

		if secrets.GithubPat == "" {
			w.WriteHeader(401)
			w.Write([]byte("This feature is currently disabled, please set the github personal access token github_pat in secrets.yaml"))
			return
		}

		deploy, ok := config.Deploys[r.Host]

		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Deploy to protect not found: " + r.Host))
			return
		}

		if deploy.Git == nil {
			w.WriteHeader(401)
			w.Write([]byte("This feature is currently disabled, please set the git config in config.yaml"))
			return
		}

		var bodyBytes []byte

		defer r.Body.Close()
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
		}

		var signature = r.Header.Get("X-Hub-Signature-256")

		mac := hmac.New(sha256.New, []byte(secrets.GithubWebhookSig))
		mac.Write([]byte(bodyBytes))
		expected := hex.EncodeToString(mac.Sum(nil))

		if "sha256="+expected != signature {
			w.WriteHeader(401)
			w.Write([]byte("This request has a bad signature, recheck the secret and ensure it isnt the id...."))
			return
		}

		if r.Header.Get("X-GitHub-Event") != "push" {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte("This event is not a push, ignoring"))
			return
		}

		var repoData struct {
			Ref        string `json:"ref"`
			Repository struct {
				FullName string `json:"full_name"`
				CloneURL string `json:"clone_url"`
			} `json:"repository"`
		}

		err := json.Unmarshal(bodyBytes, &repoData)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Error parsing json"))
			return
		}

		if !strings.EqualFold(repoData.Repository.FullName, deploy.Git.GithubRepo) {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte("This event is not for the correct repo, ignoring"))
			return
		}

		if repoData.Ref != deploy.Git.GithubRef {
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte("This event is not for the correct ref, ignoring, got: " + repoData.Ref + " expected: " + deploy.Git.GithubRef))
			return
		}

		// Create a new folder for deploy
		deployID := uuid.New().String()

		go func() {
			inDeploy.Lock()
			defer inDeploy.Unlock()

			_, err = discord.ChannelMessageSendEmbeds(secrets.LogChannel, []*discordgo.MessageEmbed{
				{
					Title: "Deploying to VPS",
					Fields: []*discordgo.MessageEmbedField{
						{
							Name:   "Deploy ID",
							Value:  deployID,
							Inline: true,
						},
						{
							Name:   "Log URL",
							Value:  deploy.URL + "/__dp/logs?id=" + deployID,
							Inline: true,
						},
					},
					Timestamp: time.Now().Format(time.RFC3339),
				},
			})

			if err != nil {
				fmt.Println(err)
			}

			err = addToDeployLog(deployID, "Started deploy on: "+time.Now().Format(time.RFC3339))

			if err != nil {
				fmt.Println(err)
			}

			err = os.MkdirAll("deploys/"+deployID, 0755)

			if err != nil {
				addToDeployLog(deployID, "Error creating deploy folder: "+err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error creating deploy folder"))
				return
			}

			// Clone repo
			_, err = git.PlainClone("deploys/"+deployID, false, &git.CloneOptions{
				URL: repoData.Repository.CloneURL,
				Auth: &githttp.BasicAuth{
					Username: secrets.GithubPat,
					Password: secrets.GithubPat,
				},
				Progress: autoLogger{DeployID: deployID},
			})

			if err != nil {
				addToDeployLog(deployID, "Error cloning repo: "+err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error cloning repo"))
				return
			}

			// Run `yarn run install in the folder`
			cmd := exec.Command("yarn", "install")
			cmd.Dir = "deploys/" + deployID
			cmd.Env = os.Environ()
			cmd.Stdout = autoLogger{DeployID: deployID}
			cmd.Stderr = autoLogger{DeployID: deployID, Error: true}

			err = cmd.Run()

			if err != nil {
				addToDeployLog(deployID, "Error running yarn install: "+err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error running yarn install"))
				return
			}

			// Run `yarn install --dev in the folder`
			cmd = exec.Command("yarn", "install", "--dev")
			cmd.Dir = "deploys/" + deployID
			cmd.Env = os.Environ()
			cmd.Stdout = autoLogger{DeployID: deployID}
			cmd.Stderr = autoLogger{DeployID: deployID, Error: true}

			err = cmd.Run()

			if err != nil {
				addToDeployLog(deployID, "Error running yarn install --dev: "+err.Error())
			}

			// Run `yarn run build in the folder`
			cmd = exec.Command("yarn", "run", "build")
			cmd.Dir = "deploys/" + deployID
			cmd.Env = os.Environ()
			cmd.Stdout = autoLogger{DeployID: deployID}
			cmd.Stderr = autoLogger{DeployID: deployID, Error: true}

			err = cmd.Run()

			if err != nil {
				addToDeployLog(deployID, "Error running yarn build: "+err.Error())

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error running yarn build"))
				return
			}

			// Remove deploy.Git.Path and move deploys/deployID to deploy.Git.Path
			err = os.Rename(deploy.Git.Path, deploy.Git.Path+"-old")

			if err != nil {
				addToDeployLog(deployID, "Error moving old deploy folder: "+err.Error())

				// Move back
				os.Rename(deploy.Git.Path+"-old", deploy.Git.Path)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error moving old deploy folder"))
				return
			}

			err = os.Rename("deploys/"+deployID, deploy.Git.Path)

			if err != nil {
				addToDeployLog(deployID, "Error moving new deploy folder: "+err.Error())

				// Move back
				os.RemoveAll(deploy.Git.Path)
				os.Rename(deploy.Git.Path+"-old", deploy.Git.Path)

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Error moving new deploy folder"))
				return
			}

			// Remove old deploy
			os.RemoveAll(deploy.Git.Path + "-old")

			addToDeployLog(deployID, "Deploy finished on: "+time.Now().Format(time.RFC3339))

			_, err = discord.ChannelMessageSendEmbeds(secrets.LogChannel, []*discordgo.MessageEmbed{
				{
					Title: "Deploy finished",
					Fields: []*discordgo.MessageEmbedField{
						{
							Name:   "Deploy ID",
							Value:  deployID,
							Inline: true,
						},
						{
							Name:   "Log URL",
							Value:  deploy.URL + "/__dp/logs?id=" + deployID,
							Inline: true,
						},
					},
					Timestamp: time.Now().Format(time.RFC3339),
				},
			})

			// Run systemctl restart deploy.Git.Service
			cmd = exec.Command("systemctl", "restart", deploy.Git.Service)
			cmd.Env = os.Environ()
			cmd.Stdout = autoLogger{DeployID: deployID}
			cmd.Stderr = autoLogger{DeployID: deployID, Error: true}

			err = cmd.Run()

			if err != nil {
				addToDeployLog(deployID, "Error restarting service: "+err.Error())
			}

			addToDeployLog(deployID, "Service restarted on: "+time.Now().Format(time.RFC3339))
		}()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(deployID))
	})
}
