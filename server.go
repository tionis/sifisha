package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/go-github/v65/github"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	gothGithub "github.com/markbates/goth/providers/github"
	"github.com/pkg/sftp"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
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
	Teams              map[string][]string
	MetaDataValidUntil time.Time
}

type server struct {
	client                   *sftp.Client
	sftpPrefix               string
	logger                   *slog.Logger
	githubUsers              map[string]githubUser
	githubUsersMutexMap      map[string]*sync.Mutex
	githubUsersMutexMapMutex sync.Mutex
	githubClientID           string
	githubClientSecret       string
	cookieStore              sessions.Store
	githubProvider           *gothGithub.Provider
}

type success struct {
	Message string
}

type forbidden struct {
	Reason string
}

type orgsTemplateInput struct {
	Orgs []string
}

type teamsTemplateInput struct {
	Org   string
	Teams []string
}

func newServer(client *sftp.Client, sftpPrefix string, logger *slog.Logger, githubClientID, githubClientSecret, sessionKey string, isHTTPS bool) (*server, error) {
	maxAge := 86400 * 30 // 30 days
	store := sessions.NewCookieStore([]byte(sessionKey))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isHTTPS

	return &server{
		client:                   client,
		logger:                   logger,
		githubUsers:              make(map[string]githubUser),
		githubUsersMutexMap:      make(map[string]*sync.Mutex),
		githubUsersMutexMapMutex: sync.Mutex{},
		githubClientID:           githubClientID,
		githubClientSecret:       githubClientSecret,
		cookieStore:              store,
	}, nil
}

func arrayContains(array []string, element string) bool {
	for _, e := range array {
		if e == element {
			return true
		}
	}
	return false
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
	var ok bool
	if user, ok = s.githubUsers[token]; ok {
		if user.MetaDataValidUntil.After(time.Now()) {
			s.logger.Debug("using cached github user", "user", user)
			return &user, nil
		} else {
			s.logger.Debug("cached github user expired", "user", user)
			delete(s.githubUsers, token)
			user, err = getGithubUserFromToken(token)
			if err != nil {
				s.logger.Error("failed to get github user", "error", err)
				return nil, fmt.Errorf("failed to get github user: %v", err)
			}
			s.githubUsers[token] = user
		}
	} else {
		s.logger.Debug("no cached github user found")
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
		user.Orgs = append(user.Orgs, org.GetLogin())
	}
	user.Teams = map[string][]string{}
	teams, _, err := client.Teams.ListUserTeams(context.Background(), nil)
	if err != nil {
		return user, fmt.Errorf("failed to get teams: %v", err)
	}
	for _, team := range teams {
		orgName := team.GetOrganization().GetLogin()
		teamName := team.GetSlug()
		if _, ok := user.Teams[orgName]; !ok {
			user.Teams[orgName] = []string{}
		}
		user.Teams[orgName] = append(user.Teams[orgName], teamName)
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

func (s *server) handleForbidden(w http.ResponseWriter, _ *http.Request, reason string) {
	rawForbidden, err := fs.ReadFile(assets, "assets/templates/forbidden.tmpl")
	if err != nil {
		s.logger.Error("failed to read forbidden templates", "error", err)
		http.Error(w, "failed to read forbidden templates", http.StatusInternalServerError)
		return
	}
	tmpl, err := template.New("forbidden").Parse(string(rawForbidden))
	if err != nil {
		s.logger.Error("failed to parse forbidden templates", "error", err)
		http.Error(w, "failed to parse forbidden templates", http.StatusInternalServerError)
		return
	}
	data := forbidden{
		Reason: reason,
	}
	w.WriteHeader(http.StatusForbidden)
	err = tmpl.Execute(w, data)
	if err != nil {
		s.logger.Error("failed to execute forbidden templates", "error", err)
		http.Error(w, "failed to execute forbidden templates", http.StatusInternalServerError)
		return
	}
}

func (s *server) ServeGithubShare(w http.ResponseWriter, r *http.Request) {
	session, err := s.cookieStore.Get(r, "github")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.logger.Debug("no session found")
			http.Redirect(w, r, "/oauth/github", http.StatusFound)
			return
		}
		s.logger.Error("failed to get session", "error", err)
		http.Error(w, "failed to get session", http.StatusInternalServerError)
		return
	}
	accessToken, ok := session.Values["AccessToken"].(string)
	if !ok {
		s.logger.Debug("no access token in session")
		http.Redirect(w, r, "/oauth/github", http.StatusFound)
		return
	}
	user, err := s.getGithubUser(accessToken)
	if err != nil {
		s.logger.Error("failed to get github user", "error", err)
		//http.Error(w, "failed to get github user", http.StatusInternalServerError)
		// TODO temporary workaround, check for tokenExpired or tokenInvalid errors in the future
		// and redirect to /oauth/github
		// if error is another, throw error back at user and into logger
		http.Redirect(w, r, "/oauth/github", http.StatusFound)
		return
	}
	s.logger.Debug("got github user", "user", user)

	pathParts := strings.Split(strings.TrimSuffix(r.URL.Path[1:], "/"), "/")
	var org, team string
	if len(pathParts) > 1 {
		org = pathParts[1]
	}
	if len(pathParts) > 2 {
		team = pathParts[2]
	}
	s.logger.Debug("url parts", "org", org, "team", team, "urlParts", pathParts)
	if org == "" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
			return
		}
		var orgIntersection []string
		orgsPath := path.Join(s.sftpPrefix, "github")
		orgs, err := s.client.ReadDir(orgsPath)
		if err != nil {
			s.logger.Error("failed to read orgs", "error", err)
			http.Error(w, "failed to read orgs", http.StatusInternalServerError)
			return
		}
		for _, org := range orgs {
			if arrayContains(user.Orgs, org.Name()) {
				orgIntersection = append(orgIntersection, org.Name())
			}
		}
		rawOrgsTmpl, err := fs.ReadFile(assets, "assets/templates/orgs.tmpl")
		if err != nil {
			// TODO precompile and cache templates in RAM
			s.logger.Error("failed to read orgs templates", "error", err)
			http.Error(w, "failed to read orgs templates", http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("orgs").Parse(string(rawOrgsTmpl))
		if err != nil {
			s.logger.Error("failed to parse orgs templates", "error", err)
			http.Error(w, "failed to parse orgs templates", http.StatusInternalServerError)
			return
		}
		data := orgsTemplateInput{
			Orgs: orgIntersection,
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			s.logger.Error("failed to execute orgs templates", "error", err)
			http.Error(w, "failed to execute orgs templates", http.StatusInternalServerError)
			return
		}
		return
	} else {
		if !arrayContains(user.Orgs, org) {
			s.handleForbidden(w, r, "not in org")
			return
		}
	}
	if team == "" {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
			return
		}
		var teamIntersection []string
		teamsPath := path.Join(s.sftpPrefix, "github", org)
		teams, err := s.client.ReadDir(teamsPath)
		if err != nil {
			if errors.Is(err, sftp.ErrSSHFxNoSuchFile) {
				// Do not leak existence of org share
				teams = []os.FileInfo{}
			} else {
				s.logger.Error("failed to read teams", "error", err)
				http.Error(w, "failed to read teams", http.StatusInternalServerError)
				return
			}
		}
		userTeams := user.Teams[org]
		for _, team := range teams {
			if arrayContains(userTeams, team.Name()) {
				teamIntersection = append(teamIntersection, team.Name())
			}
		}
		rawTeamsTmpl, err := fs.ReadFile(assets, "assets/templates/teams.tmpl")
		if err != nil {
			s.logger.Error("failed to read teams templates", "error", err)
			http.Error(w, "failed to read teams templates", http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("teams").Parse(string(rawTeamsTmpl))
		if err != nil {
			s.logger.Error("failed to parse teams templates", "error", err)
			http.Error(w, "failed to parse teams templates", http.StatusInternalServerError)
			return
		}
		data := teamsTemplateInput{
			Org:   org,
			Teams: teamIntersection,
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			s.logger.Error("failed to execute teams templates", "error", err)
			http.Error(w, "failed to execute teams templates", http.StatusInternalServerError)
			return
		}
		return
	} else if team != "_" {
		userTeams := user.Teams[org]
		if !arrayContains(userTeams, team) {
			s.handleForbidden(w, r, "not in team")
			return
		}
	}

	// TODO do normal file serving and listing, do not follow symlinks though, instead handle them as redirects
	// (or use _redirects file?)
	// (or use special name.link file?) (hide .link extension if it does not collide with a real file)
	//   .link files might either link relative or absolute to the root of the share location
	// switch to https://github.com/thatoddmailbox/sftpfs for this, so that http.Fs can be used?
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

func (s *server) oauthInit(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Add("provider", provider)
	r.URL.RawQuery = q.Encode()

	gothic.BeginAuthHandler(w, r)
}

func (s *server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Add("provider", provider)
	r.URL.RawQuery = q.Encode()
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		s.logger.Error("failed to complete user auth", "error", err)
		http.Error(w, "failed to complete user auth", http.StatusInternalServerError)
		return
	}

	session, err := s.cookieStore.New(r, "github")
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}
	session.Values["AccessToken"] = user.AccessToken
	err = s.cookieStore.Save(r, w, session)
	if err != nil {
		s.logger.Error("failed to save session", "error", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	rawSuccessTmpl, err := fs.ReadFile(assets, "assets/templates/success.tmpl")
	if err != nil {
		s.logger.Error("failed to read success templates", "error", err)
		http.Error(w, "failed to read success templates", http.StatusInternalServerError)
		return
	}
	tmpl, err := template.New("success").Parse(string(rawSuccessTmpl))
	if err != nil {
		s.logger.Error("failed to parse success templates", "error", err)
		http.Error(w, "failed to parse success templates", http.StatusInternalServerError)
		return
	}
	data := success{
		Message: "Successfully logged in using " + provider,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		s.logger.Error("failed to execute success templates", "error", err)
		http.Error(w, "failed to execute success templates", http.StatusInternalServerError)
		return
	}
}

func (s *server) oauthLogout(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Add("provider", provider)
	r.URL.RawQuery = q.Encode()
	err := gothic.Logout(w, r)
	if err != nil {
		s.logger.Error("failed to logout", "error", err)
		http.Error(w, "failed to logout", http.StatusInternalServerError)
		return
	}
}

func (s *server) serve(listenAddr string) error {
	r := chi.NewRouter()

	s.githubProvider = gothGithub.New(
		s.githubClientID,
		s.githubClientSecret,
		"http://localhost:2848/oauth/github/callback",
		"read:org",
		"read:user")

	goth.UseProviders(
		s.githubProvider)

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Set a timeout value on the request context (ctx), that will signal
	// through ctx.Done() that the request has timed out and further
	// processing should be stopped.
	r.Use(middleware.Timeout(60 * time.Second))

	// Serve static assets
	r.Get("/", s.handleAsset)
	r.Get("/favicon.ico", s.handleAsset)
	r.Get("/robots.txt", s.handleAsset)
	r.Get("/index.html", s.handleAsset)
	r.Get("/.well-known/*", s.handleAsset)
	r.Get("/static/*", s.handleAsset)

	// Handle auth
	r.Get("/oauth/{provider}", s.oauthInit)
	r.Get("/oauth/{provider}/callback", s.oauthCallback)
	r.Get("/oauth/{provider}/logout", s.oauthLogout)

	// Handle shares
	r.Get("/gh/*", s.ServeGithubShare)
	r.Get("/gh", s.ServeGithubShare)
	r.Get("/*", s.ServeShare)

	return http.ListenAndServe(listenAddr, r)
}
