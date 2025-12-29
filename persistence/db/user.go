package db

import (
	"errors"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/user"
)

func NewUserRepository(cfg conf.Persistence) (user.Repository, error) {
	filename := cfg.Host + "/" + cfg.Name + ".db"
	if cfg.InMem {
		filename = "file::memory:?cache=shared"
	}

	db, err := gorm.Open(sqlite.Open(filename), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(
		&User{}, &SocialAccount{},
	)

	repo := new(userRepository)
	repo.db = db
	return repo, nil
}

type userRepository struct {
	db *gorm.DB
}

func (repo *userRepository) Store(u *user.User) error {
	user := NewUser(u) // convert Domain to Data model

	return repo.db.Transaction(func(tx *gorm.DB) error {
		// First, delete existing social accounts
		if err := tx.Unscoped().
			Where("user_id = ?", user.ID).
			Delete(&SocialAccount{}).
			Error; err != nil {
			return err
		}

		// Then, save the user
		return tx.Save(user).Error
	})
}

func (repo *userRepository) Delete(u *user.User) error {
	user := NewUser(u) // convert Domain to Data model

	result := repo.db.Unscoped().Delete(
		&SocialAccount{},
		"user_id = ?", user.ID)

	if err := result.Error; err != nil {
		return err
	}

	result = repo.db.Delete(user)
	return result.Error
}

func (repo *userRepository) ListAll() ([]*user.User, error) {
	var users []*User

	result := repo.db.Preload("Accounts").Find(&users)
	if err := result.Error; err != nil {
		return nil, err
	}

	results := make([]*user.User, 0)
	for _, u := range users {
		results = append(results, u.reconstitute())
	}

	return results, nil
}

func (repo *userRepository) Find(id user.UserID) (*user.User, error) {
	var u *User

	result := repo.db.Preload("Accounts").Take(&u, "id = ?", id.String())
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}

		return nil, err
	}

	user := u.reconstitute()
	return user, nil
}

func (repo *userRepository) FindByUsername(username string) (*user.User, error) {
	var u *User

	result := repo.db.Preload("Accounts").Take(&u, "username = ?", username)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}

		return nil, err
	}

	user := u.reconstitute()
	return user, nil
}

func (repo *userRepository) FindBySocialID(socialID user.SocialID) (*user.User, error) {
	var u *User
	result := repo.db.
		Preload("Accounts").
		Joins("INNER JOIN social_accounts ON social_accounts.user_id = users.id").
		Take(&u, "social_accounts.social_id = ?", socialID)

	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}

		return nil, err
	}

	user := u.reconstitute()
	return user, nil
}

func (repo *userRepository) Close() error {
	return nil
}

func (repo *userRepository) Truncate() error {
	err := repo.db.Exec("DELETE FROM social_accounts").Error
	if err != nil {
		return err
	}

	return repo.db.Exec("DELETE FROM users").Error
}
