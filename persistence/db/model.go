package db

import (
	"gorm.io/gorm"

	"github.com/flarexio/core/events"
	"github.com/flarexio/core/model"
	"github.com/flarexio/identity/user"
)

type User struct {
	ID       string `gorm:"primaryKey"`
	Username string
	Name     string
	Email    string
	Status   user.Status
	Accounts []*SocialAccount
	DataModel
}

func NewUser(u *user.User) *User {
	accounts := make([]*SocialAccount, len(u.Accounts))
	for i, a := range u.Accounts {
		accounts[i] = NewSocialAccount(a, u)
	}

	return &User{
		ID:       u.ID.String(),
		Username: u.Username,
		Name:     u.Name,
		Email:    u.Email,
		Status:   u.Status,
		Accounts: accounts,
		DataModel: DataModel{
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
			DeletedAt: gorm.DeletedAt{
				Time:  u.DeletedAt,
				Valid: !u.DeletedAt.IsZero(),
			},
		},
	}
}

func (u *User) reconstitute() *user.User {
	id, err := user.ParseID(u.ID)
	if err != nil {
		panic(err.Error())
	}

	accounts := make([]*user.SocialAccount, len(u.Accounts))
	for i, a := range u.Accounts {
		accounts[i] = a.reconstitute()
	}

	return &user.User{
		ID:       id,
		Username: u.Username,
		Name:     u.Name,
		Email:    u.Email,
		Status:   u.Status,
		Accounts: accounts,
		Model: model.Model{
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
			DeletedAt: u.DeletedAt.Time,
		},
		EventStore: events.NewEventStore(),
	}
}

type SocialAccount struct {
	UserID   string        `gorm:"primaryKey"`
	SocialID user.SocialID `gorm:"primaryKey"`
	Provider user.SocialProvider
	DataModel
}

func NewSocialAccount(a *user.SocialAccount, u *user.User) *SocialAccount {
	return &SocialAccount{
		UserID:   u.ID.String(),
		SocialID: a.SocialID,
		Provider: a.Provider,
		DataModel: DataModel{
			CreatedAt: a.CreatedAt,
			UpdatedAt: a.UpdatedAt,
			DeletedAt: gorm.DeletedAt{
				Time:  a.DeletedAt,
				Valid: !a.DeletedAt.IsZero(),
			},
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
