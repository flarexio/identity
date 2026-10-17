package inmem

import (
	"sync"

	"github.com/flarexio/identity/user"
)

func NewUserRepository() (user.Repository, error) {
	repo := new(userRepository)
	repo.reset()
	return repo, nil
}

type socialKey struct {
	provider user.SocialProvider
	socialID user.SocialID
}

// userRepository keeps one copy of each user and indexes pointing at its ID.
// Users go in and come out as clones, so no caller ever shares state with
// the store or with another caller.
type userRepository struct {
	users     map[user.UserID]*user.User
	usernames map[string]user.UserID
	socials   map[socialKey]user.UserID
	sync.RWMutex
}

func (repo *userRepository) reset() {
	repo.users = make(map[user.UserID]*user.User)
	repo.usernames = make(map[string]user.UserID)
	repo.socials = make(map[socialKey]user.UserID)
}

func (repo *userRepository) Store(u *user.User) error {
	repo.Lock()
	defer repo.Unlock()

	if id, ok := repo.usernames[u.Username]; ok && id != u.ID {
		return user.ErrUsernameTaken
	}

	for _, a := range u.Accounts {
		if id, ok := repo.socials[socialKey{a.Provider, a.SocialID}]; ok && id != u.ID {
			return user.ErrSocialAccountExists
		}
	}

	if old, ok := repo.users[u.ID]; ok {
		repo.unindex(old)
	}

	u = u.Clone()
	u.EventStore = nil

	repo.users[u.ID] = u
	repo.usernames[u.Username] = u.ID
	for _, a := range u.Accounts {
		repo.socials[socialKey{a.Provider, a.SocialID}] = u.ID
	}

	return nil
}

func (repo *userRepository) unindex(u *user.User) {
	delete(repo.usernames, u.Username)
	for _, a := range u.Accounts {
		delete(repo.socials, socialKey{a.Provider, a.SocialID})
	}
}

func (repo *userRepository) Delete(u *user.User) error {
	repo.Lock()
	defer repo.Unlock()

	old, ok := repo.users[u.ID]
	if !ok {
		return nil
	}

	repo.unindex(old)
	delete(repo.users, u.ID)
	return nil
}

func (repo *userRepository) ListAll() ([]*user.User, error) {
	repo.RLock()
	defer repo.RUnlock()

	users := make([]*user.User, 0, len(repo.users))
	for _, u := range repo.users {
		users = append(users, u.Clone())
	}

	return users, nil
}

func (repo *userRepository) Find(id user.UserID) (*user.User, error) {
	repo.RLock()
	defer repo.RUnlock()

	return repo.find(id)
}

func (repo *userRepository) find(id user.UserID) (*user.User, error) {
	u, ok := repo.users[id]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	return u.Clone(), nil
}

func (repo *userRepository) FindByUsername(username string) (*user.User, error) {
	repo.RLock()
	defer repo.RUnlock()

	id, ok := repo.usernames[username]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	return repo.find(id)
}

func (repo *userRepository) FindBySocialID(provider user.SocialProvider, socialID user.SocialID) (*user.User, error) {
	repo.RLock()
	defer repo.RUnlock()

	id, ok := repo.socials[socialKey{provider, socialID}]
	if !ok {
		return nil, user.ErrUserNotFound
	}

	return repo.find(id)
}

func (repo *userRepository) Close() error {
	return nil
}

func (repo *userRepository) Truncate() error {
	repo.Lock()
	defer repo.Unlock()

	repo.reset()
	return nil
}
