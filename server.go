package main

import (
	"embed"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed all:assets
var assets embed.FS

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
	serverUrl                string
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
	Org         string
	Teams       []string
	NoUserTeams bool
	ClientID    string
}

type templateFile struct {
	Name   string
	Target string
	Size   string
}

type templateFileSlice []templateFile

func (t templateFileSlice) Len() int {
	return len(t)
}

func (t templateFileSlice) Less(i, j int) bool {
	return t[i].Name < t[j].Name
}

func (t templateFileSlice) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

type templateDir struct {
	Name string
}

type templateDirSlice []templateDir

func (t templateDirSlice) Len() int {
	return len(t)
}

func (t templateDirSlice) Less(i, j int) bool {
	return t[i].Name < t[j].Name
}

func (t templateDirSlice) Swap(i, j int) {
	t[i], t[j] = t[j], t[i]
}

type dirTemplateInput struct {
	Files          []templateFile
	Dirs           []templateDir
	CurrentPath    string
	CurrentDir     string
	PathOneLevelUp string
}

func newServer(client *sftp.Client, sftpPrefix, serverURL string, logger *slog.Logger, githubClientID, githubClientSecret, sessionKey string, isHTTPS bool) (*server, error) {
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
		serverUrl:                serverURL,
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

var forbiddenPaths = regexp.MustCompile(`^/users\.json$|^/.*/auth\.yml$`)

func (s *server) ServeShare(w http.ResponseWriter, r *http.Request) {
	if forbiddenPaths.MatchString(r.URL.Path) {
		s.handleForbidden(w, r, "access forbidden")
		return
	}

	// TODO
	// split path into parts

	// check if sftp:$prefix/share/$path exists
	// yes: check if is file
	//  yes: serve it
	//  not: list files (redirect to $path/ if not already)

	pathParts := splitPath(r.URL.Path)
	var aclFiles []string
	for i := len(pathParts); i > 0; i-- {
		aclFiles = append(aclFiles, path.Join(s.sftpPrefix, path.Join(pathParts[:i]...), ".auth"))
	}
	// check aclFile
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
		userTeamCount := 0
		for _, teams := range user.Teams {
			userTeamCount += len(teams)
		}
		data := teamsTemplateInput{
			Org:         org,
			Teams:       teamIntersection,
			NoUserTeams: userTeamCount == 0,
			ClientID:    s.githubClientID,
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

	filePath := path.Join(s.sftpPrefix, "github", org, team, path.Join(pathParts[3:]...))
	stat, err := s.client.Stat(filePath)
	if err != nil {
		s.logger.Error("failed to stat filePath", "filePath", filePath, "error", err)
		http.Error(w, "failed to stat filePath", http.StatusInternalServerError)
		return
	}
	var doFileListing bool
	if stat.IsDir() {
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusFound)
			return
		}
		_, err := s.client.Stat(path.Join(filePath, "index.html"))
		if err != nil {
			doFileListing = true
		} else {
			filePath = path.Join(filePath, "index.html")
		}
	}
	if doFileListing {
		files, err := s.client.ReadDir(filePath)
		if err != nil {
			s.logger.Error("failed to read dir", "filePath", filePath, "error", err)
			http.Error(w, "failed to read dir", http.StatusInternalServerError)
			return
		}
		rawDirTmpl, err := fs.ReadFile(assets, "assets/templates/dir.tmpl")
		if err != nil {
			s.logger.Error("failed to read dir templates", "error", err)
			http.Error(w, "failed to read dir templates", http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("dir").Parse(string(rawDirTmpl))
		if err != nil {
			s.logger.Error("failed to parse dir templates", "error", err)
			http.Error(w, "failed to parse dir templates", http.StatusInternalServerError)
			return
		}

		var templateFiles templateFileSlice
		var templateDirs templateDirSlice
		for _, file := range files {
			name := file.Name()
			if name != "auth.yml" {
				if file.IsDir() {
					templateDirs = append(templateDirs, templateDir{
						Name: name,
					})
				} else {
					if strings.HasSuffix(name, ".link") {
						target, err := s.client.OpenFile(path.Join(filePath, name), os.O_RDONLY)
						defer func(target *sftp.File) {
							err := target.Close()
							if err != nil {
								s.logger.Error("failed to close link file", "error", err)
							}
						}(target)
						if err != nil {
							s.logger.Error("failed to open link file", "error", err)
							http.Error(w, "failed to open link file", http.StatusInternalServerError)
							return
						}
						targetBytes := make([]byte, file.Size())
						_, err = target.Read(targetBytes)
						if err != nil {
							s.logger.Error("failed to read link file", "error", err)
							http.Error(w, "failed to read link file", http.StatusInternalServerError)
							return
						}
						templateFiles = append(templateFiles, templateFile{
							Name:   name,
							Size:   ByteCountIEC(file.Size()),
							Target: string(targetBytes)})
					} else {
						templateFiles = append(templateFiles, templateFile{
							Name:   name,
							Size:   ByteCountIEC(file.Size()),
							Target: name,
						})
					}
				}
			}
		}

		// sort file and dir lists
		sort.Sort(&templateFiles)
		sort.Sort(&templateDirs)

		data := dirTemplateInput{
			Files:          templateFiles,
			Dirs:           templateDirs,
			CurrentDir:     pathParts[len(pathParts)-1],
			CurrentPath:    r.URL.Path,
			PathOneLevelUp: path.Join(r.URL.Path, ".."),
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			s.logger.Error("failed to execute dir templates", "error", err)
			http.Error(w, "failed to execute dir templates", http.StatusInternalServerError)
			return
		}
	} else {
		if strings.HasSuffix(r.URL.Path, ".link") {
			target, err := s.client.OpenFile(filePath, os.O_RDONLY)
			defer func(target *sftp.File) {
				err := target.Close()
				if err != nil {
					s.logger.Error("failed to close link file", "error", err)
				}
			}(target)
			if err != nil {
				s.logger.Error("failed to open link file", "error", err)
				http.Error(w, "failed to open link file", http.StatusInternalServerError)
				return
			}
			targetBytes := make([]byte, stat.Size())
			_, err = target.Read(targetBytes)
			if err != nil {
				s.logger.Error("failed to read link file", "error", err)
				http.Error(w, "failed to read link file", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, string(targetBytes), http.StatusFound)
			return
		}

		file, err := s.client.OpenFile(filePath, os.O_RDONLY)
		defer func(file *sftp.File) {
			err := file.Close()
			if err != nil {
				s.logger.Error("failed to close file", "error", err)
			}
		}(file)
		if err != nil {
			s.logger.Error("failed to open file", "error", err)
			http.Error(w, "failed to open file", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), file)
	}
}

func (s *server) handleAsset(w http.ResponseWriter, r *http.Request) {
	assetFs, err := fs.Sub(assets, "assets")
	if err != nil {
		s.logger.Error("failed to get asset fs", "error", err)
		http.Error(w, "failed to get https://github.com/thatoddmailbox/sftpfsasset fs", http.StatusInternalServerError)
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

	session, err := s.cookieStore.Get(r, provider)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.logger.Debug("no session found")
			http.Redirect(w, r, "/oauth/"+provider, http.StatusFound)
			return
		}
		s.logger.Error("failed to get session", "error", err)
		http.Error(w, "failed to get session", http.StatusInternalServerError)
		return
	}
	session.Options.MaxAge = -1

	err = s.cookieStore.Save(r, w, session)
	if err != nil {
		s.logger.Error("failed to save session", "error", err)
		http.Error(w, "failed to save session", http.StatusInternalServerError)
		return
	}

	rawTemplate, err := fs.ReadFile(assets, "assets/templates/success.tmpl")
	if err != nil {
		s.logger.Error("failed to read success templates", "error", err)
		http.Error(w, "failed to read success templates", http.StatusInternalServerError)
		return
	}
	tmpl, err := template.New("success").Parse(string(rawTemplate))
	if err != nil {
		s.logger.Error("failed to parse success templates", "error", err)
		http.Error(w, "failed to parse success templates", http.StatusInternalServerError)
		return
	}
	data := success{
		Message: "Successfully logged out of " + provider,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		s.logger.Error("failed to execute success templates", "error", err)
		http.Error(w, "failed to execute success templates", http.StatusInternalServerError)
		return
	}
}

func (s *server) githubUserInfo(w http.ResponseWriter, r *http.Request) {
	session, err := s.cookieStore.Get(r, "github")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.logger.Debug("no session found")
			http.Error(w, "no session found", http.StatusUnauthorized)
			return
		}
		s.logger.Error("failed to get session", "error", err)
		http.Error(w, "failed to get session", http.StatusInternalServerError)
		return
	}
	accessToken, ok := session.Values["AccessToken"].(string)
	if !ok {
		s.logger.Debug("no access token in session")
		http.Error(w, "no access token in session", http.StatusUnauthorized)
		return
	}
	user, err := s.getGithubUser(accessToken)
	if err != nil {
		s.logger.Error("failed to get github user", "error", err)
		http.Error(w, "failed to get github user", http.StatusInternalServerError)
		return
	}
	s.logger.Debug("got github user", "user", user)
	_, err = w.Write([]byte(fmt.Sprint("User: ", user.Name, "\nOrgs: ", user.Orgs, "\nTeams: ", user.Teams)))
	if err != nil {
		s.logger.Error("failed to write response", "error", err)
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

func (s *server) serve(listenAddr string) error {
	r := chi.NewRouter()

	s.githubProvider = gothGithub.New(
		s.githubClientID,
		s.githubClientSecret,
		s.serverUrl+"/oauth/github/callback",
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
	r.Get("/info/github/user", s.githubUserInfo)

	// Handle shares
	r.Get("/gh/*", s.ServeGithubShare)
	r.Get("/gh", s.ServeGithubShare)
	r.Get("/*", s.ServeShare)

	return http.ListenAndServe(listenAddr, r)
}
