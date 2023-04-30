package main

import "time"

type Config struct {
	Deploys map[string]Deploy `yaml:"deploys" validate:"required,dive"`

	// Maps a perm to a SQL statement taking a user id and returning a boolean column
	Perms map[string]string `yaml:"perms" validate:"required"`

	// Port to listen on
	Port int `yaml:"port" validate:"required"`
}

type Secrets struct {
	ClientID     string `yaml:"client_id" validate:"required"`
	ClientSecret string `yaml:"client_secret" validate:"required"`
	DatabaseURL  string `yaml:"database_url" validate:"required"`
	RedisURL     string `yaml:"redis_url" validate:"required"`
	BotToken     string `yaml:"bot_token" validate:"required"`
	DPSecret     string `yaml:"dp_secret" validate:"required"`
}

type Deploy struct {
	URL           string        `yaml:"url"`
	Description   string        `yaml:"description"`
	Enabled       bool          `yaml:"enabled"`
	Perms         []string      `yaml:"perms"`
	AllowedIDS    []string      `yaml:"allowed_ids"`
	To            string        `yaml:"to"`
	Git           *DeployGit    `yaml:"git"`
	API           *DeployAPI    `yaml:"api"`
	Bypass        *DeployBypass `yaml:"bypass"`
	Strict        bool          `yaml:"strict"`
	MFA           bool          `yaml:"mfa"`
	CheckIP       bool          `yaml:"check_ip"`        // Only enable if you can be sure that IPs will not change, seems to be broken under Discord right now
	HideLoginHTML bool          `yaml:"hide_login_html"` // Disables the login page and directly redirects to Discord
}

type DeployGit struct {
	GithubRepo    string   `yaml:"github_repo"`
	GithubRef     string   `yaml:"github_ref"`
	Path          string   `yaml:"path"`
	Service       string   `yaml:"service"`
	BuildCommands []string `yaml:"build_commands"`
}

type DeployAPI struct {
	CorrespondingDeploy string   `yaml:"corresponding_deploy"`
	AllowHeaders        []string `yaml:"allow_headers"`
}

type DeployBypass struct {
	StartsWith []string `yaml:"starts_with"`
	EndsWith   []string `yaml:"ends_with"`
}

type RedisSession struct {
	UserID    string    `json:"user_id"`
	DeployURL string    `json:"deploy_url"`
	MFA       bool      `json:"mfa"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip"`
}

type Down struct {
	Error string
}

// Views
type LoginView struct {
	Deploy     Deploy
	CurrentURL string
	Redirect   string
	Reason     string
}

type MfaNewView struct {
	Secret string
	QRCode string
}
