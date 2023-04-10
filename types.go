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
	DPSecret         string `yaml:"dp_secret"`
}

type Deploy struct {
	URL         string        `yaml:"url"`
	Description string        `yaml:"description"`
	Enabled     bool          `yaml:"enabled"`
	Perms       []Perm        `yaml:"perms"`
	AllowedIDS  []string      `yaml:"allowed_ids"`
	To          string        `yaml:"to"`
	Git         *DeployGit    `yaml:"git"`
	API         *DeployAPI    `yaml:"api"`
	Bypass      *DeployBypass `yaml:"bypass"`
	Strict      bool          `yaml:"strict"`
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
