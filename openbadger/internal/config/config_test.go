package config

import "testing"

func TestLoadFromEnvironmentDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	if cfg.Log.Level != "info" {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "info")
	}

	if cfg.Log.Format != "json" {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, "json")
	}

	if cfg.Server.Address != ":8080" {
		t.Fatalf("Server.Address = %q, want %q", cfg.Server.Address, ":8080")
	}

	if cfg.Server.ShutdownTimeout.String() != "5s" {
		t.Fatalf("Server.ShutdownTimeout = %q, want %q", cfg.Server.ShutdownTimeout, "5s")
	}

	if cfg.Server.SchedulerInterval.String() != "1s" {
		t.Fatalf("Server.SchedulerInterval = %q, want %q", cfg.Server.SchedulerInterval, "1s")
	}

	if cfg.Server.EnrollmentToken != "" {
		t.Fatalf("Server.EnrollmentToken = %q, want empty", cfg.Server.EnrollmentToken)
	}

	if cfg.Server.AdminUsername != "" {
		t.Fatalf("Server.AdminUsername = %q, want empty", cfg.Server.AdminUsername)
	}

	if cfg.Server.AdminPassword != "" {
		t.Fatalf("Server.AdminPassword = %q, want empty", cfg.Server.AdminPassword)
	}

	if cfg.Server.AdminSessionSecret != "" {
		t.Fatalf("Server.AdminSessionSecret = %q, want empty", cfg.Server.AdminSessionSecret)
	}

	if cfg.Server.AdminSessionTTL.String() != "12h0m0s" {
		t.Fatalf("Server.AdminSessionTTL = %q, want %q", cfg.Server.AdminSessionTTL, "12h0m0s")
	}

	if cfg.Server.CredentialEncryptionKey != "" {
		t.Fatalf("Server.CredentialEncryptionKey = %q, want empty", cfg.Server.CredentialEncryptionKey)
	}

	if cfg.Server.ExpectedHeartbeatInterval.String() != "30s" {
		t.Fatalf("Server.ExpectedHeartbeatInterval = %q, want %q", cfg.Server.ExpectedHeartbeatInterval, "30s")
	}

	if cfg.Server.StaleAfterMissedHeartbeats != 3 {
		t.Fatalf("Server.StaleAfterMissedHeartbeats = %d, want %d", cfg.Server.StaleAfterMissedHeartbeats, 3)
	}

	if cfg.Server.ObservationRetention.String() != "720h0m0s" {
		t.Fatalf("Server.ObservationRetention = %q, want %q", cfg.Server.ObservationRetention, "720h0m0s")
	}

	if cfg.Collector.Name != "collector" {
		t.Fatalf("Collector.Name = %q, want %q", cfg.Collector.Name, "collector")
	}

	if cfg.Collector.ServerURL != "http://127.0.0.1:8080" {
		t.Fatalf("Collector.ServerURL = %q, want %q", cfg.Collector.ServerURL, "http://127.0.0.1:8080")
	}

	if cfg.Collector.StatePath != "collector-state.json" {
		t.Fatalf("Collector.StatePath = %q, want %q", cfg.Collector.StatePath, "collector-state.json")
	}

	if cfg.Collector.HeartbeatInterval.String() != "30s" {
		t.Fatalf("Collector.HeartbeatInterval = %q, want %q", cfg.Collector.HeartbeatInterval, "30s")
	}

	if cfg.Sensor.Name != "sensor" {
		t.Fatalf("Sensor.Name = %q, want %q", cfg.Sensor.Name, "sensor")
	}

	if cfg.Sensor.ServerURL != "http://127.0.0.1:8080" {
		t.Fatalf("Sensor.ServerURL = %q, want %q", cfg.Sensor.ServerURL, "http://127.0.0.1:8080")
	}

	if cfg.Sensor.StatePath != "sensor-state.json" {
		t.Fatalf("Sensor.StatePath = %q, want %q", cfg.Sensor.StatePath, "sensor-state.json")
	}

	if cfg.Sensor.HeartbeatInterval.String() != "30s" {
		t.Fatalf("Sensor.HeartbeatInterval = %q, want %q", cfg.Sensor.HeartbeatInterval, "30s")
	}

	if cfg.Sensor.Interface != "" {
		t.Fatalf("Sensor.Interface = %q, want empty", cfg.Sensor.Interface)
	}

	if cfg.Sensor.PCAPFile != "" {
		t.Fatalf("Sensor.PCAPFile = %q, want empty", cfg.Sensor.PCAPFile)
	}

	if cfg.Sensor.CaptureWindow.String() != "10s" {
		t.Fatalf("Sensor.CaptureWindow = %q, want %q", cfg.Sensor.CaptureWindow, "10s")
	}

	if cfg.Sensor.ReadTimeout.String() != "500ms" {
		t.Fatalf("Sensor.ReadTimeout = %q, want %q", cfg.Sensor.ReadTimeout, "500ms")
	}

	if cfg.Sensor.Promiscuous {
		t.Fatal("Sensor.Promiscuous = true, want false")
	}

	if cfg.Sensor.SnapLen != 1600 {
		t.Fatalf("Sensor.SnapLen = %d, want %d", cfg.Sensor.SnapLen, 1600)
	}

	if cfg.Sensor.FlowListenAddress != "" {
		t.Fatalf("Sensor.FlowListenAddress = %q, want empty", cfg.Sensor.FlowListenAddress)
	}

	if cfg.Sensor.FlowReadTimeout.String() != "500ms" {
		t.Fatalf("Sensor.FlowReadTimeout = %q, want %q", cfg.Sensor.FlowReadTimeout, "500ms")
	}

	if cfg.Sensor.FlowMaxDatagram != 65535 {
		t.Fatalf("Sensor.FlowMaxDatagram = %d, want %d", cfg.Sensor.FlowMaxDatagram, 65535)
	}
}

func TestLoadFromEnvironmentValues(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{
		"OPENBADGER_LOG_LEVEL":                            "debug",
		"OPENBADGER_LOG_FORMAT":                           "text",
		"OPENBADGER_SERVER_ADDRESS":                       ":9090",
		"OPENBADGER_SERVER_SHUTDOWN_TIMEOUT":              "12s",
		"OPENBADGER_SERVER_SCHEDULER_INTERVAL":            "2s",
		"OPENBADGER_SERVER_ENROLLMENT_TOKEN":              "bootstrap-token",
		"OPENBADGER_SERVER_ADMIN_USERNAME":                "admin",
		"OPENBADGER_SERVER_ADMIN_PASSWORD":                "admin-password",
		"OPENBADGER_SERVER_ADMIN_SESSION_SECRET":          "session-secret",
		"OPENBADGER_SERVER_ADMIN_SESSION_TTL":             "8h",
		"OPENBADGER_SERVER_CREDENTIAL_ENCRYPTION_KEY":     "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"OPENBADGER_SERVER_EXPECTED_HEARTBEAT_INTERVAL":   "45s",
		"OPENBADGER_SERVER_STALE_AFTER_MISSED_HEARTBEATS": "4",
		"OPENBADGER_SERVER_OBSERVATION_RETENTION":         "168h",
		"OPENBADGER_COLLECTOR_NAME":                       "collector-a",
		"OPENBADGER_COLLECTOR_SERVER_URL":                 "https://server.example.test",
		"OPENBADGER_COLLECTOR_SITE_ID":                    "site-collector",
		"OPENBADGER_COLLECTOR_ENROLLMENT_TOKEN":           "collector-bootstrap",
		"OPENBADGER_COLLECTOR_STATE_PATH":                 "/tmp/collector-state.json",
		"OPENBADGER_COLLECTOR_HEARTBEAT_INTERVAL":         "45s",
		"OPENBADGER_SENSOR_NAME":                          "sensor-a",
		"OPENBADGER_SENSOR_SERVER_URL":                    "https://sensor.example.test",
		"OPENBADGER_SENSOR_SITE_ID":                       "site-sensor",
		"OPENBADGER_SENSOR_ENROLLMENT_TOKEN":              "sensor-bootstrap",
		"OPENBADGER_SENSOR_STATE_PATH":                    "/tmp/sensor-state.json",
		"OPENBADGER_SENSOR_HEARTBEAT_INTERVAL":            "1m",
		"OPENBADGER_SENSOR_INTERFACE":                     "enp4s0",
		"OPENBADGER_SENSOR_PCAP_FILE":                     "/tmp/sensor-fixture.pcap",
		"OPENBADGER_SENSOR_CAPTURE_WINDOW":                "15s",
		"OPENBADGER_SENSOR_READ_TIMEOUT":                  "250ms",
		"OPENBADGER_SENSOR_PROMISCUOUS":                   "true",
		"OPENBADGER_SENSOR_SNAP_LEN":                      "2048",
		"OPENBADGER_SENSOR_FLOW_LISTEN_ADDRESS":           "127.0.0.1:2055",
		"OPENBADGER_SENSOR_FLOW_READ_TIMEOUT":             "750ms",
		"OPENBADGER_SENSOR_FLOW_MAX_DATAGRAM":             "9000",
		"OPENBADGER_DATABASE_URL":                         "postgres://example",
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	if cfg.Log.Level != "debug" {
		t.Fatalf("Log.Level = %q, want %q", cfg.Log.Level, "debug")
	}

	if cfg.Log.Format != "text" {
		t.Fatalf("Log.Format = %q, want %q", cfg.Log.Format, "text")
	}

	if cfg.Server.Address != ":9090" {
		t.Fatalf("Server.Address = %q, want %q", cfg.Server.Address, ":9090")
	}

	if cfg.Server.ShutdownTimeout.String() != "12s" {
		t.Fatalf("Server.ShutdownTimeout = %q, want %q", cfg.Server.ShutdownTimeout, "12s")
	}

	if cfg.Server.SchedulerInterval.String() != "2s" {
		t.Fatalf("Server.SchedulerInterval = %q, want %q", cfg.Server.SchedulerInterval, "2s")
	}

	if cfg.Server.EnrollmentToken != "bootstrap-token" {
		t.Fatalf("Server.EnrollmentToken = %q, want %q", cfg.Server.EnrollmentToken, "bootstrap-token")
	}

	if cfg.Server.AdminUsername != "admin" {
		t.Fatalf("Server.AdminUsername = %q, want %q", cfg.Server.AdminUsername, "admin")
	}

	if cfg.Server.AdminPassword != "admin-password" {
		t.Fatalf("Server.AdminPassword = %q, want %q", cfg.Server.AdminPassword, "admin-password")
	}

	if cfg.Server.AdminSessionSecret != "session-secret" {
		t.Fatalf("Server.AdminSessionSecret = %q, want %q", cfg.Server.AdminSessionSecret, "session-secret")
	}

	if cfg.Server.AdminSessionTTL.String() != "8h0m0s" {
		t.Fatalf("Server.AdminSessionTTL = %q, want %q", cfg.Server.AdminSessionTTL, "8h0m0s")
	}

	if cfg.Server.CredentialEncryptionKey != "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" {
		t.Fatalf("Server.CredentialEncryptionKey = %q, want %q", cfg.Server.CredentialEncryptionKey, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	}

	if cfg.Server.ExpectedHeartbeatInterval.String() != "45s" {
		t.Fatalf("Server.ExpectedHeartbeatInterval = %q, want %q", cfg.Server.ExpectedHeartbeatInterval, "45s")
	}

	if cfg.Server.StaleAfterMissedHeartbeats != 4 {
		t.Fatalf("Server.StaleAfterMissedHeartbeats = %d, want %d", cfg.Server.StaleAfterMissedHeartbeats, 4)
	}

	if cfg.Server.ObservationRetention.String() != "168h0m0s" {
		t.Fatalf("Server.ObservationRetention = %q, want %q", cfg.Server.ObservationRetention, "168h0m0s")
	}

	if cfg.Collector.Name != "collector-a" {
		t.Fatalf("Collector.Name = %q, want %q", cfg.Collector.Name, "collector-a")
	}

	if cfg.Collector.ServerURL != "https://server.example.test" {
		t.Fatalf("Collector.ServerURL = %q, want %q", cfg.Collector.ServerURL, "https://server.example.test")
	}

	if cfg.Collector.SiteID != "site-collector" {
		t.Fatalf("Collector.SiteID = %q, want %q", cfg.Collector.SiteID, "site-collector")
	}

	if cfg.Collector.EnrollmentToken != "collector-bootstrap" {
		t.Fatalf("Collector.EnrollmentToken = %q, want %q", cfg.Collector.EnrollmentToken, "collector-bootstrap")
	}

	if cfg.Collector.StatePath != "/tmp/collector-state.json" {
		t.Fatalf("Collector.StatePath = %q, want %q", cfg.Collector.StatePath, "/tmp/collector-state.json")
	}

	if cfg.Collector.HeartbeatInterval.String() != "45s" {
		t.Fatalf("Collector.HeartbeatInterval = %q, want %q", cfg.Collector.HeartbeatInterval, "45s")
	}

	if cfg.Sensor.Name != "sensor-a" {
		t.Fatalf("Sensor.Name = %q, want %q", cfg.Sensor.Name, "sensor-a")
	}

	if cfg.Sensor.ServerURL != "https://sensor.example.test" {
		t.Fatalf("Sensor.ServerURL = %q, want %q", cfg.Sensor.ServerURL, "https://sensor.example.test")
	}

	if cfg.Sensor.SiteID != "site-sensor" {
		t.Fatalf("Sensor.SiteID = %q, want %q", cfg.Sensor.SiteID, "site-sensor")
	}

	if cfg.Sensor.EnrollmentToken != "sensor-bootstrap" {
		t.Fatalf("Sensor.EnrollmentToken = %q, want %q", cfg.Sensor.EnrollmentToken, "sensor-bootstrap")
	}

	if cfg.Sensor.StatePath != "/tmp/sensor-state.json" {
		t.Fatalf("Sensor.StatePath = %q, want %q", cfg.Sensor.StatePath, "/tmp/sensor-state.json")
	}

	if cfg.Sensor.HeartbeatInterval.String() != "1m0s" {
		t.Fatalf("Sensor.HeartbeatInterval = %q, want %q", cfg.Sensor.HeartbeatInterval, "1m0s")
	}

	if cfg.Sensor.Interface != "enp4s0" {
		t.Fatalf("Sensor.Interface = %q, want %q", cfg.Sensor.Interface, "enp4s0")
	}

	if cfg.Sensor.PCAPFile != "/tmp/sensor-fixture.pcap" {
		t.Fatalf("Sensor.PCAPFile = %q, want %q", cfg.Sensor.PCAPFile, "/tmp/sensor-fixture.pcap")
	}

	if cfg.Sensor.CaptureWindow.String() != "15s" {
		t.Fatalf("Sensor.CaptureWindow = %q, want %q", cfg.Sensor.CaptureWindow, "15s")
	}

	if cfg.Sensor.ReadTimeout.String() != "250ms" {
		t.Fatalf("Sensor.ReadTimeout = %q, want %q", cfg.Sensor.ReadTimeout, "250ms")
	}

	if !cfg.Sensor.Promiscuous {
		t.Fatal("Sensor.Promiscuous = false, want true")
	}

	if cfg.Sensor.SnapLen != 2048 {
		t.Fatalf("Sensor.SnapLen = %d, want %d", cfg.Sensor.SnapLen, 2048)
	}

	if cfg.Sensor.FlowListenAddress != "127.0.0.1:2055" {
		t.Fatalf("Sensor.FlowListenAddress = %q, want %q", cfg.Sensor.FlowListenAddress, "127.0.0.1:2055")
	}

	if cfg.Sensor.FlowReadTimeout.String() != "750ms" {
		t.Fatalf("Sensor.FlowReadTimeout = %q, want %q", cfg.Sensor.FlowReadTimeout, "750ms")
	}

	if cfg.Sensor.FlowMaxDatagram != 9000 {
		t.Fatalf("Sensor.FlowMaxDatagram = %d, want %d", cfg.Sensor.FlowMaxDatagram, 9000)
	}

	if cfg.Database.URL != "postgres://example" {
		t.Fatalf("Database.URL = %q, want %q", cfg.Database.URL, "postgres://example")
	}
}

func TestValidateRequiresDatabaseURLAndEnrollmentTokenForServer(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	err = cfg.Validate("server")
	if err == nil {
		t.Fatal("Validate returned nil error, want error")
	}
}

func TestValidateAllowsServerWithDatabaseURLAndEnrollmentToken(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{
		"OPENBADGER_DATABASE_URL":                     "postgres://example",
		"OPENBADGER_SERVER_ENROLLMENT_TOKEN":          "bootstrap-token",
		"OPENBADGER_SERVER_ADMIN_USERNAME":            "admin",
		"OPENBADGER_SERVER_ADMIN_PASSWORD":            "admin-password",
		"OPENBADGER_SERVER_ADMIN_SESSION_SECRET":      "session-secret",
		"OPENBADGER_SERVER_CREDENTIAL_ENCRYPTION_KEY": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	if err := cfg.Validate("server"); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestValidateRequiresCollectorServerURL(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{
		"OPENBADGER_COLLECTOR_SERVER_URL": " ",
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	err = cfg.Validate("collector")
	if err == nil {
		t.Fatal("Validate returned nil error, want error")
	}
}

func TestValidateRequiresSensorServerURL(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{
		"OPENBADGER_SENSOR_SERVER_URL": " ",
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	err = cfg.Validate("sensor")
	if err == nil {
		t.Fatal("Validate returned nil error, want error")
	}
}

func TestValidateRequiresDatabaseURLForMigrate(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	err = cfg.Validate("migrate")
	if err == nil {
		t.Fatal("Validate returned nil error, want error")
	}
}

func TestValidateAllowsDatabaseURLForMigrate(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFromEnvironment(map[string]string{
		"OPENBADGER_DATABASE_URL": "postgres://example",
	})
	if err != nil {
		t.Fatalf("LoadFromEnvironment returned error: %v", err)
	}

	if err := cfg.Validate("migrate"); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}
