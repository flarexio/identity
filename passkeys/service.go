package passkeys

import "github.com/go-webauthn/webauthn/protocol"

type Service interface {
	PasskeyService
}

type PasskeyService interface {
	RegistrationService
	LoginService
	// CredentialServie
	// TransactionService
}

type RegistrationService interface {
	InitializeRegistration(userID string, username string) (*protocol.CredentialCreation, error)
	FinalizeRegistration(req *protocol.ParsedCredentialCreationData) (string, error)
}

type LoginService interface {
	InitializeLogin(userID string) (*protocol.CredentialAssertion, string, error)
	FinalizeLogin(req *protocol.ParsedCredentialAssertionData) (string, error)
}

type CredentialServie interface {
	ListCredentials(userID string) ([]*Credential, error)
	UpdateCredential(credentialID string, name string) error
	RemoveCredential(credentialID string) error
}

type TransactionService interface {
	InitializeTransaction(req *InitializeTransactionRequest) (*protocol.CredentialAssertion, string, error)
	FinalizeTransaction(req *protocol.ParsedCredentialAssertionData) (string, error)
}
