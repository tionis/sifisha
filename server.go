package main

import (
	"context"
	"embed"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/go-github/v65/github"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	gothGithub "github.com/markbates/goth/providers/github"
	"github.com/pkg/sftp"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

//go:embed all:assets
var assets embed.FS

func Assets() (fs.FS, error) {
	return fs.Sub(assets, "assets")
}

var (
	githubMetaDataValidDuration = 5 * time.Minute
)

type githubUser struct {
	Name               string
	Orgs               []string
	Teams              []string
	MetaDataValidUntil time.Time
}

type server struct {
	client                   *sftp.Client
	logger                   *slog.Logger
	githubUsers              map[string]githubUser
	githubUsersMutexMap      map[string]*sync.Mutex
	githubUsersMutexMapMutex sync.Mutex
	githubClientID           string
	githubClientSecret       string
}

func newServer(client *sftp.Client, logger *slog.Logger, githubClientID, githubClientSecret string) (*server, error) {
	return &server{
		client:                   client,
		logger:                   logger,
		githubUsers:              make(map[string]githubUser),
		githubUsersMutexMap:      make(map[string]*sync.Mutex),
		githubUsersMutexMapMutex: sync.Mutex{},
		githubClientID:           githubClientID,
		githubClientSecret:       githubClientSecret,
	}, nil
}

func (s *server) getGithubUser(token string) (*githubUser, error) {
	var userLock *sync.Mutex
	s.githubUsersMutexMapMutex.Lock()
	if _, ok := s.githubUsersMutexMap[token]; !ok {
		s.githubUsersMutexMap[token] = &sync.Mutex{}
		userLock = s.githubUsersMutexMap[token]
	} else {
		userLock = s.githubUsersMutexMap[token]
	}
	s.githubUsersMutexMapMutex.Unlock()

	userLock.Lock()
	defer userLock.Unlock()
	var user githubUser
	var err error
	if user, ok := s.githubUsers[token]; ok {
		if user.MetaDataValidUntil.After(time.Now()) {
			return &user, nil
		} else {
			delete(s.githubUsers, token)
			user, err = getGithubUserFromToken(token)
			if err != nil {
				s.logger.Error("failed to get github user", "error", err)
				return nil, fmt.Errorf("failed to get github user: %v", err)
			}
			s.githubUsers[token] = user
		}
	} else {
		user, err = getGithubUserFromToken(token)
		if err != nil {
			s.logger.Error("failed to get github user", "error", err)
			return nil, fmt.Errorf("failed to get github user: %v", err)
		}
		s.githubUsers[token] = user
	}
	return &user, nil
}

func getGithubUserFromToken(token string) (githubUser, error) {
	user := githubUser{
		MetaDataValidUntil: time.Now().Add(githubMetaDataValidDuration),
	}
	client := github.NewClient(nil).WithAuthToken(token)
	fetchedUser, _, err := client.Users.Get(context.Background(), "")
	if err != nil {
		return user, fmt.Errorf("failed to get user: %v", err)
	}
	user.Name = fetchedUser.GetName()
	user.Orgs = []string{}
	orgs, _, err := client.Organizations.List(context.Background(), user.Name, nil)
	if err != nil {
		return user, fmt.Errorf("failed to get orgs: %v", err)
	}
	for _, org := range orgs {
		user.Orgs = append(user.Orgs, org.GetName())
	}
	user.Teams = []string{}
	teams, _, err := client.Teams.ListUserTeams(context.Background(), nil)
	if err != nil {
		return user, fmt.Errorf("failed to get teams: %v", err)
	}
	for _, team := range teams {
		// name of the format org/team or for nested team org/parent_team/team
		user.Teams = append(user.Teams, team.GetSlug())
	}
	return user, nil
}

func (s *server) ServeShare(w http.ResponseWriter, r *http.Request) {
	// TODO
	// split path into parts
	// check if sftp:$prefix/share/$path exists
	// yes: check if is file
	//  yes: serve it
	//  not: list files (only if not in top level '/')
}

func (s *server) ServeGithubShare(w http.ResponseWriter, r *http.Request) {
	// TODO
	// split path into parts
	// permission checks:
	// 1. check if user is logged in, if not forward to login flow
	// 2. check if user has access to the requested path by splitting it
	//    parts[1] is the org
	//    parts[2] is the team (or no team if parts[2] == "_")
	// check if sftp:$prefix/gh/$path exists
	// yes: check if is file
	//  yes: serve it
	//  not: list files (only if not in top level '/')
}

func (s *server) handleAsset(w http.ResponseWriter, r *http.Request) {
	assetFs, err := fs.Sub(assets, "assets")
	if err != nil {
		s.logger.Error("failed to get asset fs", "error", err)
		http.Error(w, "failed to get asset fs", http.StatusInternalServerError)
		return
	}
	http.FileServer(http.FS(assetFs)).ServeHTTP(w, r)
}

func (s *server) callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := ctx.Value("provider").(string)
	q := r.URL.Query()
	q.Add("provider", provider)
	r.URL.RawQuery = q.Encode()
	_, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		s.logger.Error("failed to complete user auth", "error", err)
		http.Error(w, "failed to complete user auth", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/auth_success", http.StatusTemporaryRedirect)
}

func (s *server) signInWithProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	provider := ctx.Value("provider").(string)
	q := r.URL.Query()
	q.Add("provider", provider)
	r.URL.RawQuery = q.Encode()

	gothic.BeginAuthHandler(w, r)
}

func (s *server) serve(listenAddr string) error {
	r := chi.NewRouter()

	goth.UseProviders(
		gothGithub.New(
			s.githubClientID,
			s.githubClientSecret,
			"http://localhost:2848/oauth/github/callback"))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", s.handleAsset)
	r.Get("/favicon.ico", s.handleAsset)

	r.Get("/auth/:provider/callback", s.callbackHandler)
	r.Get("/auth/:provider", s.signInWithProvider)
	r.Get("/auth_success", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html")
		content, err := assets.ReadFile("assets/auth_success.html")
		if err != nil {
			http.Error(w, "failed to read asset", http.StatusInternalServerError)
			s.logger.Error("failed to read asset", "error", err)
			return
		}
		_, err = w.Write(content)
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
			s.logger.Error("failed to write response", "error", err)
			return
		}
	})
	// logout
	r.Get("/robots.txt", s.handleAsset)
	r.Get("/index.html", s.handleAsset)
	r.Get("/.well-known/*", s.handleAsset)
	r.Get("/static/*", s.handleAsset)
	r.Get("/gh/*", s.ServeGithubShare)
	r.Get("/*", s.ServeShare)
	return http.ListenAndServe(listenAddr, r)
}
