package config

import (
	"log"
	"log/slog"
	"time"

	"github.com/joeshaw/envdecode"
)

type Conf struct {
	Db      dbConf
	AppConf appConf
	Server  serverConf
}

type dbConf struct {
	Host     string `env:"POSTGRES_HOST,default=localhost"`
	Db       string `env:"POSTGRES_DB,default=db"`
	User     string `env:"POSTGRES_USER,default=dbuser"`
	Password string `env:"POSTGRES_PASSWORD,default=dbuser"`
	// PG SSL MODES: allow, disable
	SSLMode  string `env:"POSTGRES_SSL_MODE,default=disable"`
	Port     int    `env:"POSTGRES_PORT,default=5432"`
	MaxConns int    `env:"POSTGRES_MAX_CONNS,default=16"`
}
type appConf struct {
	// needs to be removed or made into a list a slice
	DNSServer string `env:"DNS_SEVER,default=8.8.8.8:53"`
	// temporary XApiKey for development
	XApiKey    string     `env:"X_API_KEY,default=changeme"`
	LogLevel   slog.Level `env:"LOG_LEVEL,default=info"`
	LogJson    bool       `env:"LOG_JSON,default=false"`
	LogConcise bool       `env:"LOG_CONCISE,default=false"`
}
type serverConf struct {
	APIPort      int           `env:"API_SERVER_PORT,default=9090"`
	TimeoutRead  time.Duration `env:"SERVER_TIMEOUT_READ,default=5s"`
	TimeoutIdle  time.Duration `env:"SERVER_TIMEOUT_IDLE,default=5s"`
	TimeoutWrite time.Duration `env:"SERVER_TIMEOUT_WRITE,default=5s"`
}

// AppConfig Setup and install the applications' configuration environment variables
func AppConfig() *Conf {
	var c Conf
	if err := envdecode.StrictDecode(&c); err != nil {
		log.Fatalf("Failed to decode: %s", err)
	}
	return &c
}
