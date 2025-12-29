package kv

import (
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/flarexio/identity/conf"
	"github.com/flarexio/identity/user"
)

type userRepositoryTestSuite struct {
	suite.Suite
	users user.Repository
	user  *user.User
}

func (suite *userRepositoryTestSuite) SetupSuite() {
	cfg := conf.Persistence{
		Driver: conf.BadgerDB,
		Name:   "identity",
		InMem:  true,
	}

	users, err := NewUserRepository(cfg)
	if err != nil {
		suite.Fail(err.Error())
		return
	}

	suite.users = users
}

func (suite *userRepositoryTestSuite) SetupTest() {
	// 每個測試前清空資料
	suite.users.Truncate()

	// 建立測試用戶
	u := user.NewUser("mirror770109", "Lin, Ying-Chin", "mirror770109@gmail.com")
	u.AddSocialAccount(user.GOOGLE, "100043685676652067799")
	suite.users.Store(u)

	suite.user = u
}

func (suite *userRepositoryTestSuite) TestFind() {
	user, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Equal("mirror770109", user.Username)
	suite.Len(user.Accounts, 1)
}

func (suite *userRepositoryTestSuite) TestFindByUsername() {
	user, err := suite.users.FindByUsername(suite.user.Username)
	suite.NoError(err)
	suite.Equal("mirror770109", user.Username)
}

func (suite *userRepositoryTestSuite) TestFindBySocialID() {
	sid := suite.user.Accounts[0].SocialID

	user, err := suite.users.FindBySocialID(sid)
	suite.NoError(err)
	suite.Equal("mirror770109", user.Username)
	suite.Equal(sid, user.Accounts[0].SocialID)
}

func (suite *userRepositoryTestSuite) TestAddMultipleSocialAccounts() {
	// 添加多個社交帳號
	u, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)

	u.AddSocialAccount(user.LINE, "line-user-123")
	u.AddSocialAccount(user.FACEBOOK, "fb-user-456")

	err = suite.users.Store(u)
	suite.NoError(err)

	// 驗證
	found, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Len(found.Accounts, 3)
}

func (suite *userRepositoryTestSuite) TestRemoveSocialAccount() {
	// 先添加多個帳號
	u, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)

	u.AddSocialAccount(user.LINE, "line-user-123")
	suite.users.Store(u)

	// 移除一個帳號
	u, err = suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Len(u.Accounts, 2)

	err = u.RemoveSocialAccount(user.LINE, "line-user-123")
	suite.NoError(err)

	err = suite.users.Store(u)
	suite.NoError(err)

	// 驗證
	found, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Len(found.Accounts, 1)
	suite.Equal(user.GOOGLE, found.Accounts[0].Provider)
}

func (suite *userRepositoryTestSuite) TestRemoveAndReAddSocialAccount() {
	googleID := user.SocialID("100043685676652067799")

	// 移除 Google 帳號
	u, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)

	err = u.RemoveSocialAccount(user.GOOGLE, googleID)
	suite.NoError(err)

	err = suite.users.Store(u)
	suite.NoError(err)

	// 驗證已移除
	found, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Len(found.Accounts, 0)

	// 重新添加相同的 Google 帳號
	err = found.AddSocialAccount(user.GOOGLE, googleID)
	suite.NoError(err)

	err = suite.users.Store(found)
	suite.NoError(err)

	// 驗證重新添加成功
	reAdded, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)
	suite.Len(reAdded.Accounts, 1)
	suite.Equal(user.GOOGLE, reAdded.Accounts[0].Provider)
	suite.Equal(googleID, reAdded.Accounts[0].SocialID)

	// 驗證可以透過 SocialID 找到
	byGoogle, err := suite.users.FindBySocialID(googleID)
	suite.NoError(err)
	suite.Equal(suite.user.ID, byGoogle.ID)
}

func (suite *userRepositoryTestSuite) TestDeleteUser() {
	// 刪除用戶
	u, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)

	u.Delete()
	err = suite.users.Delete(u)
	suite.NoError(err)

	// 驗證用戶已被刪除（找不到）
	_, err = suite.users.Find(suite.user.ID)
	suite.Error(err)
	suite.Equal(user.ErrUserNotFound, err)

	// 驗證無法透過 SocialID 找到
	_, err = suite.users.FindBySocialID(suite.user.Accounts[0].SocialID)
	suite.Error(err)
	suite.Equal(user.ErrUserNotFound, err)
}

func (suite *userRepositoryTestSuite) TestListAll() {
	// 創建多個用戶
	u2 := user.NewUser("user2", "User Two", "user2@example.com")
	u2.AddSocialAccount(user.LINE, "line-user-2")
	suite.users.Store(u2)

	u3 := user.NewUser("user3", "User Three", "user3@example.com")
	u3.AddSocialAccount(user.FACEBOOK, "fb-user-3")
	suite.users.Store(u3)

	// 列出所有用戶
	all, err := suite.users.ListAll()
	suite.NoError(err)
	suite.Len(all, 3)

	// 刪除一個用戶
	u2.Delete()
	suite.users.Delete(u2)

	// 驗證列表只剩 2 個
	all, err = suite.users.ListAll()
	suite.NoError(err)
	suite.Len(all, 2)
}

func (suite *userRepositoryTestSuite) TestDuplicateSocialAccount() {
	u, err := suite.users.Find(suite.user.ID)
	suite.NoError(err)

	// 嘗試添加重複的 SocialAccount
	err = u.AddSocialAccount(user.GOOGLE, "100043685676652067799")
	suite.Error(err)
	suite.Contains(err.Error(), "already exists")
}

func (suite *userRepositoryTestSuite) TearDownSuite() {
	suite.users.Truncate()
	suite.users.Close()
}

func TestUserRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(userRepositoryTestSuite))
}
