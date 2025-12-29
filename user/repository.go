package user

type Repository interface {
	// Command

	Store(u *User) error
	Delete(u *User) error

	// Query

	ListAll() ([]*User, error)
	Find(id UserID) (*User, error)
	FindByUsername(username string) (*User, error)
	FindBySocialID(socialID SocialID) (*User, error)

	// Close the repository
	Close() error

	// Remove all users from the repository (for testing purposes)
	Truncate() error
}
