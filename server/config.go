package server

import (
	"github.com/Snowlights/sso-service/common"
	"net/http"
	"time"
)

// Config configuration parameters
type Config struct {
	TokenType                   string                // token type
	AllowGetAccessRequest       bool                  // to allow GET requests for the token
	AllowedResponseTypes        []common.ResponseType // allow the authorization type
	AllowedGrantTypes           []common.GrantType    // allow the grant type
	AllowedCodeChallengeMethods []common.CodeChallengeMethod
	ForcePKCE                   bool
}

// NewConfig create to configuration instance
func NewConfig() *Config {
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []common.ResponseType{common.Code, common.Token},
		AllowedGrantTypes: []common.GrantType{
			common.AuthorizationCode,
			common.PasswordCredentials,
			common.ClientCredentials,
			common.Refreshing,
		},
		AllowedCodeChallengeMethods: []common.CodeChallengeMethod{
			common.CodeChallengePlain,
			common.CodeChallengeS256,
		},
	}
}

// AuthorizeRequest authorization request
type AuthorizeRequest struct {
	ResponseType        common.ResponseType
	ClientID            string
	Scope               string
	RedirectURI         string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod common.CodeChallengeMethod
	AccessTokenExp      time.Duration
	Request             *http.Request
}
