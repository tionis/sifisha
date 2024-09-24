package main

import (
	"context"
	"fmt"
	"github.com/google/go-github/v65/github"
	"sync"
	"time"
)

var (
	githubMetaDataValidDuration = 5 * time.Minute
)

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
