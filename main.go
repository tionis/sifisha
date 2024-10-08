package main

import (
	"encoding/base64"
	"fmt"
	"github.com/dusted-go/logging/prettylog"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/pkg/sftp"
)

func main() {
	var remotePrefix string
	var client *sftp.Client
	var logger *slog.Logger
	var sshConn *ssh.Client

	defer func(conn *ssh.Client) {
		if conn != nil {
			err := conn.Close()
			if err != nil {
				log.Println(err)
			}
		}
	}(sshConn)

	defer func(sc *sftp.Client) {
		if sc != nil {
			err := sc.Close()
			if err != nil {
				log.Println(err)
			}
		}
	}(client)

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	sshDir := path.Join(home, ".ssh")

	defaultLogLevel := os.Getenv("LOG_LEVEL")
	if defaultLogLevel == "" {
		defaultLogLevel = "INFO"
	}

	defaultServerURL := os.Getenv("SERVER_URL")
	if defaultServerURL == "" {
		defaultServerURL = "http://localhost:2848"
	}

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "remote",
				Aliases: []string{"r"},
				Usage:   "sftp remote to connect to",
				Value:   os.Getenv("SFTP_REMOTE"),
			},
			&cli.StringFlag{
				Name:  "log-level",
				Usage: "set log level (debug, info, warn, error, fatal, panic)",
				Value: defaultLogLevel,
			},
		},
		Before: func(context *cli.Context) error {
			logger, err = getLoggerFromLevelStr(context.String("log-level"))
			if err != nil {
				return fmt.Errorf("failed to create logger: %v", err)
			}

			var user, pass, host, port string
			user, pass, host, port, remotePrefix, err = parseSftpRemote(context.String("remote"))
			if err != nil {
				logger.Error("failed to parse remote", "error", err)
				return fmt.Errorf("failed to parse remote: %v", err)
			}
			logger.Debug("parsed remote", "user", user, "host", host, "port", port, "remotePrefix", remotePrefix)

			var auths []ssh.AuthMethod

			envPrivKey := os.Getenv("SSH_PRIVATE_KEY")
			if envPrivKey != "" {
				bytes := make([]byte, base64.StdEncoding.DecodedLen(len(envPrivKey)))
				_, err := base64.StdEncoding.Decode(bytes, []byte(envPrivKey))
				if err != nil {
					logger.Error("failed to decode base64 private key", "error", err)
					return fmt.Errorf("failed to decode base64 private key: %v", err)
				}
				key, err := ssh.ParsePrivateKey(bytes)
				if err != nil {
					logger.Error("failed to parse private key", "error", err, "bytesStr", string(bytes))
					return fmt.Errorf("failed to parse private key: %v", err)
				}
				auths = append(auths, ssh.PublicKeys(key))
			} else if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
				// Try to use $SSH_AUTH_SOCK which contains the path of the unix file socket that the sshd agent uses
				// for communication with other processes.
				auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
			} else if _, err := os.Stat(path.Join(sshDir, "id_ed25519")); err == nil {
				bytes, err := os.ReadFile(path.Join(sshDir, "id_ed25519"))
				if err != nil {
					return fmt.Errorf("failed to read private key: %v", err)
				}
				logger.Debug("using ed25519 private key", "key", string(bytes))
				key, err := ssh.ParsePrivateKey(bytes)
				if err != nil {
					logger.Error("failed to parse private key", "error", err)
					return fmt.Errorf("failed to parse private key: %v", err)
				}
				auths = append(auths, ssh.PublicKeys(key))
			}

			// Use password authentication if provided
			if pass != "" {
				auths = append(auths, ssh.Password(pass))
			}

			knownHosts, err := knownhosts.New(path.Join(sshDir, "known_hosts"))
			if err != nil {
				logger.Error("failed to load known hosts", "error", err)
				return fmt.Errorf("failed to load known hosts: %v", err)
			}

			// Initialize client configuration
			config := ssh.ClientConfig{
				User: user,
				Auth: auths,
				// Uncomment to ignore host key check
				//HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					if err := knownHosts(hostname, remote, key); err != nil {
						keyStr := ssh.FingerprintSHA256(key)
						keyMarshaled := ssh.MarshalAuthorizedKey(key)
						logger.Error("failed to verify host key", "error", err, "hostname", hostname, "keyFingerprint", keyStr, "key", keyMarshaled)
						return fmt.Errorf("failed to verify host key: %v", err)
					}
					return nil
				},
			}

			addr := fmt.Sprintf("%s:%s", host, port)

			logger.Info("connecting to remote", "addr", addr)

			// Connect to server
			sshConn, err = ssh.Dial("tcp", addr, &config)
			if err != nil {
				logger.Error("failed to connect to remote", "addr", addr, "error", err)
				return fmt.Errorf("failed to connect to remote: %v", err)
			}

			// Create new SFTP client
			client, err = sftp.NewClient(sshConn)
			if err != nil {
				logger.Error("failed to create sftp client", "error", err)
				return fmt.Errorf("failed to create sftp client: %v", err)
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "serve",
				Aliases: []string{"s"},
				Usage:   "start the SiFiSha proxy server",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "listen",
						Usage: "address to listen on",
						Value: "0.0.0.0:2848",
					},
					&cli.StringFlag{
						Name:  "server-url",
						Usage: "URL of the server",
						Value: defaultServerURL,
					},
				},
				Action: func(cCtx *cli.Context) error {
					server, err := newServer(
						client,
						remotePrefix,
						cCtx.String("server-url"),
						logger,
						os.Getenv("GITHUB_CLIENT_ID"),
						os.Getenv("GITHUB_CLIENT_SECRET"),
						os.Getenv("SESSION_SECRET"),
						os.Getenv("SECURE_COOKIE") == "true")
					if err != nil {
						logger.Error("failed to create server", "error", err)
						return fmt.Errorf("failed to create server: %v", err)
					}
					return server.serve(cCtx.String("listen"))
				},
			},
			{
				Name:    "ls",
				Aliases: []string{"a"},
				Usage:   "list files",
				Action: func(cCtx *cli.Context) error {
					listPath := cCtx.Args().First()
					if listPath == "" {
						listPath = "."
					}
					files, err := client.ReadDir(path.Join(strings.TrimPrefix(remotePrefix, "/"), listPath))
					if err != nil {
						return err
					}
					for _, file := range files {
						fmt.Println(file.Name())
					}
					return nil
				},
			},
			{
				Name:  "realpath",
				Usage: "get the real path of a file",
				Action: func(cCtx *cli.Context) error {
					filePath := cCtx.Args().First()
					if filePath == "" {
						return fmt.Errorf("no file path provided")
					}
					realPath, err := client.RealPath(path.Join(strings.TrimPrefix(remotePrefix, "/"), filePath))
					if err != nil {
						return err
					}
					fmt.Println(realPath)
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func parseSftpRemote(sftpUrl string) (user, pass, host, port, remotePrefix string, err error) {
	if !strings.HasPrefix(sftpUrl, "sftp://") {
		sftpUrl = "sftp://" + sftpUrl
	}
	parsedRemote, err := url.Parse(sftpUrl)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("failed to parse remote: %v", err)
	}
	user = parsedRemote.User.Username()
	pass, _ = parsedRemote.User.Password()
	host = parsedRemote.Hostname()
	port = parsedRemote.Port()
	remotePrefix = parsedRemote.Path
	if port == "" {
		port = "22"
	}
	return user, pass, host, port, remotePrefix, nil
}

func getLoggerFromLevelStr(levelStr string) (*slog.Logger, error) {
	logLevel := slog.LevelInfo
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level: %s", levelStr)
	}
	var addSource bool
	if logLevel == slog.LevelDebug {
		addSource = true
	}
	loggerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: addSource,
	}
	return slog.New(prettylog.NewHandler(loggerOpts)), nil
}
