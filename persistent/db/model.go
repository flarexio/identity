package db

import (
	"github.com/oklog/ulid/v2"
	"gorm.io/gorm"

	"github.com/mirror520/identity/model"
	"github.com/mirror520/identity/user"
)

type User struct {
	ID       string `gorm:"primaryKey"`
	Username string
	Name     string
	Email    string
	Status   user.Status
	Accounts []*SocialAccount
	model.DataModel
}

func NewUser(u *user.User) *User {
	accounts := make([]*SocialAccount, len(u.Accounts))
	for i, a := range u.Accounts {
		accounts[i] = NewSocialAccount(a, u)
	}

	deletedAt := gorm.DeletedAt{
		Time: u.DeletedAt,
	}
	if u.DeletedAt.IsZero() {
		deletedAt.Valid = false
	}

	return &User{
		ID:       u.ID.String(),
		Username: u.Username,
		Name:     u.Name,
		Email:    u.Email,
		Status:   u.Status,
		Accounts: accounts,
		DataModel: model.DataModel{
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
			DeletedAt: deletedAt,
		},
	}
}

func (u *User) reconstitute() *user.User {
	accounts := make([]*user.SocialAccount, len(u.Accounts))
	for i, a := range u.Accounts {
		accounts[i] = a.reconstitute()
	}

	return &user.User{
		ID:       user.UserID(ulid.MustParse(u.ID)),
		Username: u.Username,
		Name:     u.Name,
		Email:    u.Email,
		Status:   u.Status,
		Accounts: accounts,
	}
}

type SocialAccount struct {
	UserID   string        `gorm:"primaryKey"`
	SocialID user.SocialID `gorm:"primaryKey"`
	Provider user.SocialProvider
	model.DataModel
}

func NewSocialAccount(a *user.SocialAccount, u *user.User) *SocialAccount {
	deletedAt := gorm.DeletedAt{
		Time: a.DeletedAt,
	}

	if a.DeletedAt.IsZero() {
		deletedAt.Valid = false
	}

	return &SocialAccount{
		UserID:   u.ID.String(),
		SocialID: a.SocialID,
		Provider: a.Provider,
		DataModel: model.DataModel{
			CreatedAt: a.CreatedAt,
			UpdatedAt: a.UpdatedAt,
			DeletedAt: deletedAt,
		},
	}
}

func (a *SocialAccount) reconstitute() *user.SocialAccount {
	return &user.SocialAccount{
		SocialID: a.SocialID,
		Provider: a.Provider,
		Model: model.Model{
			CreatedAt: a.CreatedAt,
			UpdatedAt: a.UpdatedAt,
			DeletedAt: a.DeletedAt.Time,
		},
	}
}
