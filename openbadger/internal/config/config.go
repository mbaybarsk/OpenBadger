package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Log       LoggingConfig   `envPrefix:"OPENBADGER_LOG_"`
	Server    ServerConfig    `envPrefix:"OPENBADGER_SERVER_"`
	Collector CollectorConfig `envPrefix:"OPENBADGER_COLLECTOR_"`
	Sensor    SensorConfig    `envPrefix:"OPENBADGER_SENSOR_"`
	Database  DatabaseConfig  `envPrefix:"OPENBADGER_DATABASE_"`
}

type LoggingConfig struct {
	Level  string `env:"LEVEL" envDefault:"info"`
	Format string `env:"FORMAT" envDefault:"json"`
}

type ServerConfig struct {
	Address                    string        `env:"ADDRESS" envDefault:":8080"`
	ShutdownTimeout            time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"5s"`
	SchedulerInterval          time.Duration `env:"SCHEDULER_INTERVAL" envDefault:"1s"`
	EnrollmentToken            string        `env:"ENROLLMENT_TOKEN"`
	AdminUsername              string        `env:"ADMIN_USERNAME"`
	AdminPassword              string        `env:"ADMIN_PASSWORD"`
	AdminSessionSecret         string        `env:"ADMIN_SESSION_SECRET"`
	AdminSessionTTL            time.Duration `env:"ADMIN_SESSION_TTL" envDefault:"12h"`
	CredentialEncryptionKey    string        `env:"CREDENTIAL_ENCRYPTION_KEY"`
	ExpectedHeartbeatInterval  time.Duration `env:"EXPECTED_HEARTBEAT_INTERVAL" envDefault:"30s"`
	StaleAfterMissedHeartbeats int           `env:"STALE_AFTER_MISSED_HEARTBEATS" envDefault:"3"`
	ObservationRetention       time.Duration `env:"OBSERVATION_RETENTION" envDefault:"720h"`
}

type CollectorConfig struct {
	Name              string        `env:"NAME" envDefault:"collector"`
	ServerURL         string        `env:"SERVER_URL" envDefault:"http://127.0.0.1:8080"`
	SiteID            string        `env:"SITE_ID"`
	EnrollmentToken   string        `env:"ENROLLMENT_TOKEN"`
	StatePath         string        `env:"STATE_PATH" envDefault:"collector-state.json"`
	HeartbeatInterval time.Duration `env:"HEARTBEAT_INTERVAL" envDefault:"30s"`
}

type SensorConfig struct {
	Name              string        `env:"NAME" envDefault:"sensor"`
	ServerURL         string        `env:"SERVER_URL" envDefault:"http://127.0.0.1:8080"`
	SiteID            string        `env:"SITE_ID"`
	EnrollmentToken   string        `env:"ENROLLMENT_TOKEN"`
	StatePath         string        `env:"STATE_PATH" envDefault:"sensor-state.json"`
	HeartbeatInterval time.Duration `env:"HEARTBEAT_INTERVAL" envDefault:"30s"`
	Interface         string        `env:"INTERFACE"`
	PCAPFile          string        `env:"PCAP_FILE"`
	CaptureWindow     time.Duration `env:"CAPTURE_WINDOW" envDefault:"10s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"500ms"`
	Promiscuous       bool          `env:"PROMISCUOUS" envDefault:"false"`
	SnapLen           int32         `env:"SNAP_LEN" envDefault:"1600"`
	FlowListenAddress string        `env:"FLOW_LISTEN_ADDRESS"`
	FlowReadTimeout   time.Duration `env:"FLOW_READ_TIMEOUT" envDefault:"500ms"`
	FlowMaxDatagram   int           `env:"FLOW_MAX_DATAGRAM" envDefault:"65535"`
}

type DatabaseConfig struct {
	URL string `env:"URL"`
}

func Load() (Config, error) {
	return LoadFromEnvironment(nil)
}

func LoadFromEnvironment(environment map[string]string) (Config, error) {
	var cfg Config

	options := env.Options{}
	if environment != nil {
		options.Environment = environment
	}

	if err := env.ParseWithOptions(&cfg, options); err != nil {
		return Config{}, fmt.Errorf("parse environment config: %w", err)
	}

	return cfg, nil
}

func (c Config) Validate(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "server":
		if strings.TrimSpace(c.Database.URL) == "" {
			return fmt.Errorf("database url is required for mode %q", mode)
		}

		if strings.TrimSpace(c.Server.EnrollmentToken) == "" {
			return fmt.Errorf("server enrollment token is required for mode %q", mode)
		}

		if strings.TrimSpace(c.Server.AdminUsername) == "" {
			return fmt.Errorf("server admin username is required for mode %q", mode)
		}

		if c.Server.AdminPassword == "" {
			return fmt.Errorf("server admin password is required for mode %q", mode)
		}

		if strings.TrimSpace(c.Server.AdminSessionSecret) == "" {
			return fmt.Errorf("server admin session secret is required for mode %q", mode)
		}

		if strings.TrimSpace(c.Server.CredentialEncryptionKey) == "" {
			return fmt.Errorf("server credential encryption key is required for mode %q", mode)
		}

		if c.Server.ExpectedHeartbeatInterval <= 0 {
			return fmt.Errorf("server expected heartbeat interval is required for mode %q", mode)
		}

		if c.Server.StaleAfterMissedHeartbeats <= 0 {
			return fmt.Errorf("server stale heartbeat miss count is required for mode %q", mode)
		}

		if c.Server.ObservationRetention < 0 {
			return fmt.Errorf("server observation retention is invalid for mode %q", mode)
		}
	case "collector":
		if strings.TrimSpace(c.Collector.ServerURL) == "" {
			return fmt.Errorf("collector server url is required for mode %q", mode)
		}
	case "sensor":
		if strings.TrimSpace(c.Sensor.ServerURL) == "" {
			return fmt.Errorf("sensor server url is required for mode %q", mode)
		}
	case "migrate":
		if strings.TrimSpace(c.Database.URL) == "" {
			return fmt.Errorf("database url is required for mode %q", mode)
		}
	}

	return nil
}
