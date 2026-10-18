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

	if err := db.AutoMigrate(&User{}, &SocialAccount{}); err != nil {
		return nil, err
	}

	repo := new(userRepository)
	repo.db = db
	return repo, nil
}

type userRepository struct {
	db *gorm.DB
}

func (repo *userRepository) Store(u *user.User) error {
	row := NewUser(u) // convert Domain to Data model

	return repo.db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&User{}).
			Where("username = ? AND id <> ?", row.Username, row.ID).
			Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return user.ErrUsernameTaken
		}

		for _, a := range row.Accounts {
			if err := tx.Model(&SocialAccount{}).
				Where("provider = ? AND social_id = ? AND user_id <> ?", a.Provider, a.SocialID, row.ID).
				Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				return user.ErrSocialAccountExists
			}
		}

		// First, delete existing social accounts
		if err := tx.Unscoped().
			Where("user_id = ?", row.ID).
			Delete(&SocialAccount{}).
			Error; err != nil {
			return err
		}

		// Then, save the user
		return tx.Save(row).Error
	})
}

func (repo *userRepository) Delete(u *user.User) error {
	row := NewUser(u) // convert Domain to Data model

	return repo.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Delete(&SocialAccount{}, "user_id = ?", row.ID).Error; err != nil {
			return err
		}

		return tx.Delete(row).Error
	})
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

	return u.reconstitute(), nil
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

	return u.reconstitute(), nil
}

func (repo *userRepository) FindBySocialID(provider user.SocialProvider, socialID user.SocialID) (*user.User, error) {
	var u *User
	result := repo.db.
		Preload("Accounts").
		Joins("INNER JOIN social_accounts ON social_accounts.user_id = users.id").
		Take(&u, "social_accounts.provider = ? AND social_accounts.social_id = ?", provider, socialID)

	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, user.ErrUserNotFound
		}

		return nil, err
	}

	return u.reconstitute(), nil
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
