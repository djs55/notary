package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/bugsnag/bugsnag-go"
	"github.com/docker/notary/trustmanager"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const envPrefix = "NOTARY_TESTING_ENV_PREFIX"

const (
	Cert = "../fixtures/notary-server.crt"
	Key  = "../fixtures/notary-server.key"
	Root = "../fixtures/root-ca.crt"
)

// initializes a viper object with test configuration
func configure(jsonConfig string) *viper.Viper {
	config := viper.New()
	SetupViper(config, envPrefix)
	config.SetConfigType("json")
	config.ReadConfig(bytes.NewBuffer([]byte(jsonConfig)))
	return config
}

// Sets the environment variables in the given map, prefixed by envPrefix.
func setupEnvironmentVariables(t *testing.T, vars map[string]string) {
	for k, v := range vars {
		err := os.Setenv(fmt.Sprintf("%s_%s", envPrefix, k), v)
		require.NoError(t, err)
	}
}

// Unsets whatever environment variables were set with this map
func cleanupEnvironmentVariables(t *testing.T, vars map[string]string) {
	for k := range vars {
		err := os.Unsetenv(fmt.Sprintf("%s_%s", envPrefix, k))
		require.NoError(t, err)
	}

}

// An error is returned if the log level is not parsable
func TestParseInvalidLogLevel(t *testing.T) {
	_, err := ParseLogLevel(configure(`{"logging": {"level": "horatio"}}`),
		logrus.DebugLevel)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid logrus Level")
}

// If there is no logging level configured it is set to the default level
func TestParseNoLogLevel(t *testing.T) {
	empties := []string{`{}`, `{"logging": {}}`}
	for _, configJSON := range empties {
		lvl, err := ParseLogLevel(configure(configJSON), logrus.DebugLevel)
		require.NoError(t, err)
		require.Equal(t, logrus.DebugLevel, lvl)
	}
}

// If there is logging level configured, it is set to the configured one
func TestParseLogLevel(t *testing.T) {
	lvl, err := ParseLogLevel(configure(`{"logging": {"level": "error"}}`),
		logrus.DebugLevel)
	require.NoError(t, err)
	require.Equal(t, logrus.ErrorLevel, lvl)
}

func TestParseLogLevelWithEnvironmentVariables(t *testing.T) {
	vars := map[string]string{"LOGGING_LEVEL": "error"}
	setupEnvironmentVariables(t, vars)
	defer cleanupEnvironmentVariables(t, vars)

	lvl, err := ParseLogLevel(configure(`{}`),
		logrus.DebugLevel)
	require.NoError(t, err)
	require.Equal(t, logrus.ErrorLevel, lvl)
}

// An error is returned if there's no API key
func TestParseInvalidBugsnag(t *testing.T) {
	_, err := ParseBugsnag(configure(
		`{"reporting": {"bugsnag": {"endpoint": "http://12345"}}}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "must provide an API key")
}

// If there's no bugsnag, a nil pointer is returned
func TestParseNoBugsnag(t *testing.T) {
	empties := []string{`{}`, `{"reporting": {}}`}
	for _, configJSON := range empties {
		bugconf, err := ParseBugsnag(configure(configJSON))
		require.NoError(t, err)
		require.Nil(t, bugconf)
	}
}

func TestParseBugsnag(t *testing.T) {
	config := configure(`{
		"reporting": {
			"bugsnag": {
				"api_key": "12345",
				"release_stage": "production",
				"endpoint": "http://1234.com"
			}
		}
	}`)

	expected := bugsnag.Configuration{
		APIKey:       "12345",
		ReleaseStage: "production",
		Endpoint:     "http://1234.com",
	}

	bugconf, err := ParseBugsnag(config)
	require.NoError(t, err)
	require.Equal(t, expected, *bugconf)
}

func TestParseBugsnagWithEnvironmentVariables(t *testing.T) {
	config := configure(`{
		"reporting": {
			"bugsnag": {
				"api_key": "12345",
				"release_stage": "staging"
			}
		}
	}`)

	vars := map[string]string{
		"REPORTING_BUGSNAG_RELEASE_STAGE": "production",
		"REPORTING_BUGSNAG_ENDPOINT":      "http://1234.com",
	}
	setupEnvironmentVariables(t, vars)
	defer cleanupEnvironmentVariables(t, vars)

	expected := bugsnag.Configuration{
		APIKey:       "12345",
		ReleaseStage: "production",
		Endpoint:     "http://1234.com",
	}

	bugconf, err := ParseBugsnag(config)
	require.NoError(t, err)
	require.Equal(t, expected, *bugconf)
}

// If the storage backend is invalid or not provided, an error is returned.
func TestParseInvalidStorageBackend(t *testing.T) {
	invalids := []string{
		`{"storage": {"backend": "postgres", "db_url": "1234"}}`,
		`{"storage": {"db_url": "12345"}}`,
		`{"storage": {}}`,
		`{}`,
	}
	for _, configJSON := range invalids {
		_, err := ParseStorage(configure(configJSON),
			[]string{MySQLBackend, SqliteBackend})
		require.Error(t, err, fmt.Sprintf("'%s' should be an error", configJSON))
		require.Contains(t, err.Error(),
			"must specify one of these supported backends: mysql, sqlite3")
	}
}

// If there is no DB url for non-memory backends, an error is returned.
func TestParseInvalidStorageNoDBSource(t *testing.T) {
	invalids := []string{
		`{"storage": {"backend": "%s"}}`,
		`{"storage": {"backend": "%s", "db_url": ""}}`,
	}
	for _, backend := range []string{MySQLBackend, SqliteBackend} {
		for _, configJSONFmt := range invalids {
			configJSON := fmt.Sprintf(configJSONFmt, backend)
			_, err := ParseStorage(configure(configJSON),
				[]string{MySQLBackend, SqliteBackend})
			require.Error(t, err, fmt.Sprintf("'%s' should be an error", configJSON))
			require.Contains(t, err.Error(),
				fmt.Sprintf("must provide a non-empty database source for %s", backend))
		}
	}
}

// If a memory storage backend is specified, no DB URL is necessary for a
// successful storage parse.
func TestParseStorageMemoryStore(t *testing.T) {
	config := configure(`{"storage": {"backend": "MEMORY"}}`)
	expected := Storage{Backend: MemoryBackend}

	store, err := ParseStorage(config, []string{MySQLBackend, MemoryBackend})
	require.NoError(t, err)
	require.Equal(t, expected, *store)
}

// A supported backend with DB source will be successfully parsed.
func TestParseStorageDBStore(t *testing.T) {
	config := configure(`{
		"storage": {
			"backend": "MySQL",
			"db_url": "username:passord@tcp(hostname:1234)/dbname"
		}
	}`)

	expected := Storage{
		Backend: "mysql",
		Source:  "username:passord@tcp(hostname:1234)/dbname",
	}

	store, err := ParseStorage(config, []string{"mysql"})
	require.NoError(t, err)
	require.Equal(t, expected, *store)
}

func TestParseStorageWithEnvironmentVariables(t *testing.T) {
	config := configure(`{
		"storage": {
			"db_url": "username:passord@tcp(hostname:1234)/dbname"
		}
	}`)

	vars := map[string]string{"STORAGE_BACKEND": "MySQL"}
	setupEnvironmentVariables(t, vars)
	defer cleanupEnvironmentVariables(t, vars)

	expected := Storage{
		Backend: "mysql",
		Source:  "username:passord@tcp(hostname:1234)/dbname",
	}

	store, err := ParseStorage(config, []string{"mysql"})
	require.NoError(t, err)
	require.Equal(t, expected, *store)
}

// If TLS is required and the parameters are missing, an error is returned
func TestParseTLSNoTLSWhenRequired(t *testing.T) {
	invalids := []string{
		fmt.Sprintf(`{"server": {"tls_cert_file": "%s"}}`, Cert),
		fmt.Sprintf(`{"server": {"tls_key_file": "%s"}}`, Key),
	}
	for _, configJSON := range invalids {
		_, err := ParseServerTLS(configure(configJSON), true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	}
}

// If TLS is not required and the cert/key are partially provided, an error is returned
func TestParseTLSPartialTLS(t *testing.T) {
	invalids := []string{
		fmt.Sprintf(`{"server": {"tls_cert_file": "%s"}}`, Cert),
		fmt.Sprintf(`{"server": {"tls_key_file": "%s"}}`, Key),
	}
	for _, configJSON := range invalids {
		_, err := ParseServerTLS(configure(configJSON), false)
		require.Error(t, err)
		require.Contains(t, err.Error(),
			"either include both a cert and key file, or no TLS information at all to disable TLS")
	}
}

func TestParseTLSNoTLSNotRequired(t *testing.T) {
	config := configure(`{
		"server": {}
	}`)

	tlsConfig, err := ParseServerTLS(config, false)
	require.NoError(t, err)
	require.Nil(t, tlsConfig)
}

func TestParseTLSWithTLS(t *testing.T) {
	config := configure(fmt.Sprintf(`{
		"server": {
			"tls_cert_file": "%s",
			"tls_key_file": "%s",
			"client_ca_file": "%s"
		}
	}`, Cert, Key, Root))

	tlsConfig, err := ParseServerTLS(config, false)
	require.NoError(t, err)

	expectedCert, err := tls.LoadX509KeyPair(Cert, Key)
	require.NoError(t, err)

	expectedRoot, err := trustmanager.LoadCertFromFile(Root)
	require.NoError(t, err)

	require.Len(t, tlsConfig.Certificates, 1)
	require.True(t, reflect.DeepEqual(expectedCert, tlsConfig.Certificates[0]))

	subjects := tlsConfig.ClientCAs.Subjects()
	require.Len(t, subjects, 1)
	require.True(t, bytes.Equal(expectedRoot.RawSubject, subjects[0]))
	require.Equal(t, tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
}

func TestParseTLSWithTLSRelativeToConfigFile(t *testing.T) {
	currDir, err := os.Getwd()
	require.NoError(t, err)

	config := configure(fmt.Sprintf(`{
		"server": {
			"tls_cert_file": "%s",
			"tls_key_file": "%s",
			"client_ca_file": ""
		}
	}`, Cert, filepath.Clean(filepath.Join(currDir, Key))))
	config.SetConfigFile(filepath.Join(currDir, "me.json"))

	tlsConfig, err := ParseServerTLS(config, false)
	require.NoError(t, err)

	expectedCert, err := tls.LoadX509KeyPair(Cert, Key)
	require.NoError(t, err)

	require.Len(t, tlsConfig.Certificates, 1)
	require.True(t, reflect.DeepEqual(expectedCert, tlsConfig.Certificates[0]))

	require.Nil(t, tlsConfig.ClientCAs)
	require.Equal(t, tlsConfig.ClientAuth, tls.NoClientCert)
}

func TestParseTLSWithEnvironmentVariables(t *testing.T) {
	config := configure(fmt.Sprintf(`{
		"server": {
			"tls_cert_file": "%s",
			"client_ca_file": "nosuchfile"
		}
	}`, Cert))

	vars := map[string]string{
		"SERVER_TLS_KEY_FILE":   Key,
		"SERVER_CLIENT_CA_FILE": Root,
	}
	setupEnvironmentVariables(t, vars)
	defer cleanupEnvironmentVariables(t, vars)

	tlsConfig, err := ParseServerTLS(config, true)
	require.NoError(t, err)

	expectedCert, err := tls.LoadX509KeyPair(Cert, Key)
	require.NoError(t, err)

	expectedRoot, err := trustmanager.LoadCertFromFile(Root)
	require.NoError(t, err)

	require.Len(t, tlsConfig.Certificates, 1)
	require.True(t, reflect.DeepEqual(expectedCert, tlsConfig.Certificates[0]))

	subjects := tlsConfig.ClientCAs.Subjects()
	require.Len(t, subjects, 1)
	require.True(t, bytes.Equal(expectedRoot.RawSubject, subjects[0]))
	require.Equal(t, tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
}

func TestParseViperWithInvalidFile(t *testing.T) {
	v := viper.New()
	SetupViper(v, envPrefix)

	err := ParseViper(v, "Chronicle_Of_Dark_Secrets.json")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Could not read config")
}

func TestParseViperWithValidFile(t *testing.T) {
	file, err := os.Create("/tmp/Chronicle_Of_Dark_Secrets.json")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	file.WriteString(`{"logging": {"level": "debug"}}`)

	v := viper.New()
	SetupViper(v, envPrefix)

	err = ParseViper(v, "/tmp/Chronicle_Of_Dark_Secrets.json")
	require.NoError(t, err)

	require.Equal(t, "debug", v.GetString("logging.level"))
}
