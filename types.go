package main

type Config struct {
	Deploys map[string]Deploy `yaml:"deploys"`
}

type Secrets struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	DatabaseURL  string `yaml:"database_url"`
	RedisURL     string `yaml:"redis_url"`
}

type Deploy struct {
	URL         string `yaml:"url"`
	Description string `yaml:"description"`
	Enabled     bool   `yaml:"enabled"`
	Perms       []Perm `yaml:"perms"`
	To          string `yaml:"to"`
}

type RedisSession struct {
	UserID    string `json:"user_id"`
	DeployURL string `json:"deploy_url"`
	IP        string `json:"ip"`
}

type Perm = string

const (
	PermAdmin = "admin"
)

type Down struct {
	Error string
}
