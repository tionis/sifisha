package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/pkg/sftp"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	sshDir := path.Join(home, ".ssh")
	var defaultSshKey string
	if os.Getenv("SSH_KEY_PATH") != "" {
		defaultSshKey = os.Getenv("SSH_KEY_PATH")
	} else {
		defaultSshKey = path.Join(sshDir, "id_ed25519")
	}
	sshKeyContents := os.Getenv("SSH_KEY_CONTENTS")
	var remotePrefix string
	var client *sftp.Client

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "remote",
				Aliases:  []string{"r"},
				Required: true,
				Usage:    "sftp remote to connect to",
			},
			&cli.StringFlag{
				Name:     "key",
				Aliases:  []string{"k"},
				Required: false,
				Usage:    "path to private key",
				Value:    defaultSshKey,
			},
			&cli.StringFlag{
				Name:  "host-key",
				Usage: "host key to verify against",
				Value: os.Getenv("SSH_HOST_KEY"),
			},
		},
		Before: func(context *cli.Context) error {
			parsedRemote, err := url.Parse(context.String("remote"))
			if err != nil {
				return err
			}
			user := parsedRemote.User.Username()
			pass, _ := parsedRemote.User.Password()
			host := parsedRemote.Hostname()
			port := parsedRemote.Port()
			remotePrefix = parsedRemote.Path
			if port == "" {
				port = "22"
			}

			var hostKey ssh.PublicKey
			if context.String("host-key") == "" {
				hostKey = getHostKey(host)
			} else {
				hostKeyString := context.String("host-key")
				hostKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(hostKeyString))
			}

			_, err = fmt.Fprintf(os.Stdout, "Connecting to %s ...\n", host)
			if err != nil {
				return err
			}

			var auths []ssh.AuthMethod

			// Try to use $SSH_AUTH_SOCK which contains the path of the unix file socket that the sshd agent uses
			// for communication with other processes.
			if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
				auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
			}

			// Use password authentication if provided
			if pass != "" {
				auths = append(auths, ssh.Password(pass))
			}

			if sshKeyContents != "" {
				signer, err := ssh.ParsePrivateKey([]byte(sshKeyContents))
				if err != nil {
					return err
				}
				auths = append(auths, ssh.PublicKeys(signer))
			} else if pass == "" {
				keyPath := context.String("key")
				key, err := os.ReadFile(keyPath)
				if err != nil {
					return err
				}
				signer, err := ssh.ParsePrivateKey(key)
				if err != nil {
					return err
				}
				auths = append(auths, ssh.PublicKeys(signer))
			}

			// Initialize client configuration
			config := ssh.ClientConfig{
				User: user,
				Auth: auths,
				// Uncomment to ignore host key check
				//HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				HostKeyCallback: ssh.FixedHostKey(hostKey),
			}

			addr := fmt.Sprintf("%s:%s", host, port)

			// Connect to server
			conn, err := ssh.Dial("tcp", addr, &config)
			if err != nil {
				_, err = fmt.Fprintf(os.Stderr, "Failed to connect to [%s]: %v\n", addr, err)
				if err != nil {
					return err
				}
				os.Exit(1)
			}

			defer func(conn *ssh.Client) {
				err := conn.Close()
				if err != nil {
					log.Println(err)
				}
			}(conn)

			// Create new SFTP client
			client, err = sftp.NewClient(conn)
			if err != nil {
				_, err = fmt.Fprintf(os.Stderr, "Unable to start SFTP subsystem: %v\n", err)
				if err != nil {
					return err
				}
				os.Exit(1)
			}
			//defer func(sc *sftp.Client) {
			//	err := sc.Close()
			//	if err != nil {
			//		log.Println(err)
			//	}
			//}(sc)
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "ls",
				Aliases: []string{"a"},
				Usage:   "list files",
				Action: func(cCtx *cli.Context) error {
					listPath := cCtx.Args().First()
					if listPath == "" {
						listPath = "."
					}
					files, err := client.ReadDir(path.Join(remotePrefix, listPath))
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
				Name:    "complete",
				Aliases: []string{"c"},
				Usage:   "complete a task on the list",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("completed task: ", cCtx.Args().First())
					return nil
				},
			},
			{
				Name:    "template",
				Aliases: []string{"t"},
				Usage:   "options for task templates",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "add a new template",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("new task template: ", cCtx.Args().First())
							return nil
						},
					},
					{
						Name:  "remove",
						Usage: "remove an existing template",
						Action: func(cCtx *cli.Context) error {
							fmt.Println("removed task template: ", cCtx.Args().First())
							return nil
						},
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// Get host key from local known hosts
func getHostKey(host string) ssh.PublicKey {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Unable to read known_hosts file: %v\n", err)
		if err != nil {
			return nil
		}
		os.Exit(1)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println(err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				_, err := fmt.Fprintf(os.Stderr, "Error parsing %q: %v\n", fields[2], err)
				if err != nil {
					return nil
				}
				os.Exit(1)
			}
			break
		}
	}

	if hostKey == nil {
		_, err := fmt.Fprintf(os.Stderr, "No hostkey found for %s", host)
		if err != nil {
			return nil
		}
		os.Exit(1)
	}

	return hostKey
}
