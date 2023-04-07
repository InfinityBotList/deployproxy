package main

type Config struct {
	Deploys map[string]Deploy `yaml:"deploys"`
}

type Secrets struct {
	ClientID         string `yaml:"client_id"`
	ClientSecret     string `yaml:"client_secret"`
	DatabaseURL      string `yaml:"database_url"`
	RedisURL         string `yaml:"redis_url"`
	GithubWebhookSig string `yaml:"github_webhook_sig"`
	GithubPat        string `yaml:"github_pat"`
	BotToken         string `yaml:"bot_token"`
	LogChannel       string `yaml:"log_channel"`
}

type Deploy struct {
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
	Enabled     bool   `yaml:"enabled"`
	Perms       []Perm `yaml:"perms"`
	To          string `yaml:"to"`
	GithubRepo  string `yaml:"github_repo"`
	GithubRef   string `yaml:"github_ref"`
}

type LoginView struct {
	Deploy     Deploy
	CurrentURL string
}

type RedisSession struct {
	UserID      string `json:"user_id"`
	DeployURL   string `json:"deploy_url"`
	IP          string `json:"ip"`
	LastChecked int64  `json:"last_checked"`
}

type Perm = string

const (
	PermAdmin = "admin"
)

type Down struct {
	Error string
}
