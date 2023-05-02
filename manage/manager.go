package manage

import (
	"context"
	"github.com/Snowlights/sso-service/common"
	"github.com/Snowlights/sso-service/generates"
	"github.com/Snowlights/sso-service/model"
	"time"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager() *Manager {
	m := NewManager()
	// default implementation
	m.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())

	return m
}

// NewManager create to authorization management instance
func NewManager() *Manager {
	return &Manager{
		gtcfg:       make(map[common.GrantType]*Config),
		validateURI: DefaultValidateURI,
	}
}

// Manager provide authorization management
type Manager struct {
	codeExp           time.Duration
	gtcfg             map[common.GrantType]*Config
	rcfg              *RefreshingConfig
	validateURI       ValidateURIHandler
	authorizeGenerate common.AuthorizeGenerate
	accessGenerate    common.AccessGenerate
	tokenStore        common.TokenStore
	clientStore       common.ClientStore
}

// get grant type config
func (m *Manager) grantConfig(gt common.GrantType) *Config {
	if c, ok := m.gtcfg[gt]; ok && c != nil {
		return c
	}
	switch gt {
	case common.AuthorizationCode:
		return DefaultAuthorizeCodeTokenCfg
	case common.Implicit:
		return DefaultImplicitTokenCfg
	case common.PasswordCredentials:
		return DefaultPasswordTokenCfg
	case common.ClientCredentials:
		return DefaultClientTokenCfg
	}
	return &Config{}
}

// SetAuthorizeCodeExp set the authorization code expiration time
func (m *Manager) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

// SetAuthorizeCodeTokenCfg set the authorization code grant token config
func (m *Manager) SetAuthorizeCodeTokenCfg(cfg *Config) {
	m.gtcfg[common.AuthorizationCode] = cfg
}

// SetImplicitTokenCfg set the implicit grant token config
func (m *Manager) SetImplicitTokenCfg(cfg *Config) {
	m.gtcfg[common.Implicit] = cfg
}

// SetPasswordTokenCfg set the password grant token config
func (m *Manager) SetPasswordTokenCfg(cfg *Config) {
	m.gtcfg[common.PasswordCredentials] = cfg
}

// SetClientTokenCfg set the client grant token config
func (m *Manager) SetClientTokenCfg(cfg *Config) {
	m.gtcfg[common.ClientCredentials] = cfg
}

// SetRefreshTokenCfg set the refreshing token config
func (m *Manager) SetRefreshTokenCfg(cfg *RefreshingConfig) {
	m.rcfg = cfg
}

// SetValidateURIHandler set the validates that RedirectURI is contained in baseURI
func (m *Manager) SetValidateURIHandler(handler ValidateURIHandler) {
	m.validateURI = handler
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *Manager) MapAuthorizeGenerate(gen common.AuthorizeGenerate) {
	m.authorizeGenerate = gen
}

// MapAccessGenerate mapping the access token generate interface
func (m *Manager) MapAccessGenerate(gen common.AccessGenerate) {
	m.accessGenerate = gen
}

// MapClientStorage mapping the client store interface
func (m *Manager) MapClientStorage(stor common.ClientStore) {
	m.clientStore = stor
}

// MustClientStorage mandatory mapping the client store interface
func (m *Manager) MustClientStorage(stor common.ClientStore, err error) {
	if err != nil {
		panic(err.Error())
	}
	m.clientStore = stor
}

// MapTokenStorage mapping the token store interface
func (m *Manager) MapTokenStorage(stor common.TokenStore) {
	m.tokenStore = stor
}

// MustTokenStorage mandatory mapping the token store interface
func (m *Manager) MustTokenStorage(stor common.TokenStore, err error) {
	if err != nil {
		panic(err)
	}
	m.tokenStore = stor
}

// GetClient get the client information
func (m *Manager) GetClient(ctx context.Context, clientID string) (cli common.ClientInfo, err error) {
	cli, err = m.clientStore.GetByID(ctx, clientID)
	if err != nil {
		return
	} else if cli == nil {
		err = common.ErrInvalidClient
	}
	return
}

// GenerateAuthToken generate the authorization token(code)
func (m *Manager) GenerateAuthToken(ctx context.Context, rt common.ResponseType, tgr *common.TokenGenerateRequest) (common.TokenInfo, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	} else if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	ti := model.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	td := &common.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}
	switch rt {
	case common.Code:
		codeExp := m.codeExp
		if codeExp == 0 {
			codeExp = DefaultCodeExp
		}
		ti.SetCodeCreateAt(createAt)
		ti.SetCodeExpiresIn(codeExp)
		if exp := tgr.AccessTokenExp; exp > 0 {
			ti.SetAccessExpiresIn(exp)
		}
		if tgr.CodeChallenge != "" {
			ti.SetCodeChallenge(tgr.CodeChallenge)
			ti.SetCodeChallengeMethod(tgr.CodeChallengeMethod)
		}

		tv, err := m.authorizeGenerate.Token(ctx, td)
		if err != nil {
			return nil, err
		}
		ti.SetCode(tv)
	case common.Token:
		// set access token expires
		icfg := m.grantConfig(common.Implicit)
		aexp := icfg.AccessTokenExp
		if exp := tgr.AccessTokenExp; exp > 0 {
			aexp = exp
		}
		ti.SetAccessCreateAt(createAt)
		ti.SetAccessExpiresIn(aexp)

		if icfg.IsGenerateRefresh {
			ti.SetRefreshCreateAt(createAt)
			ti.SetRefreshExpiresIn(icfg.RefreshTokenExp)
		}

		tv, rv, err := m.accessGenerate.Token(ctx, td, icfg.IsGenerateRefresh)
		if err != nil {
			return nil, err
		}
		ti.SetAccess(tv)

		if rv != "" {
			ti.SetRefresh(rv)
		}
	}

	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

// get authorization code data
func (m *Manager) getAuthorizationCode(ctx context.Context, code string) (common.TokenInfo, error) {
	ti, err := m.tokenStore.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetCode() != code || ti.GetCodeCreateAt().Add(ti.GetCodeExpiresIn()).Before(time.Now()) {
		return nil, common.ErrInvalidAuthorizeCode
	}
	return ti, nil
}

// delete authorization code data
func (m *Manager) delAuthorizationCode(ctx context.Context, code string) error {
	return m.tokenStore.RemoveByCode(ctx, code)
}

// get and delete authorization code data
func (m *Manager) getAndDelAuthorizationCode(ctx context.Context, tgr *common.TokenGenerateRequest) (common.TokenInfo, error) {
	code := tgr.Code
	ti, err := m.getAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	} else if ti.GetClientID() != tgr.ClientID {
		return nil, common.ErrInvalidAuthorizeCode
	} else if codeURI := ti.GetRedirectURI(); codeURI != "" && codeURI != tgr.RedirectURI {
		return nil, common.ErrInvalidAuthorizeCode
	}

	err = m.delAuthorizationCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return ti, nil
}

func (m *Manager) validateCodeChallenge(ti common.TokenInfo, ver string) error {
	cc := ti.GetCodeChallenge()
	// early return
	if cc == "" && ver == "" {
		return nil
	}
	if cc == "" {
		return common.ErrMissingCodeVerifier
	}
	if ver == "" {
		return common.ErrMissingCodeVerifier
	}
	ccm := ti.GetCodeChallengeMethod()
	if ccm.String() == "" {
		ccm = common.CodeChallengePlain
	}
	if !ccm.Validate(cc, ver) {
		return common.ErrInvalidCodeChallenge
	}
	return nil
}

// GenerateAccessToken generate the access token
func (m *Manager) GenerateAccessToken(ctx context.Context, gt common.GrantType, tgr *common.TokenGenerateRequest) (common.TokenInfo, error) {
	cli, err := m.GetClient(ctx, tgr.ClientID)
	if err != nil {
		return nil, err
	}
	if cliPass, ok := cli.(common.ClientPasswordVerifier); ok {
		if !cliPass.VerifyPassword(tgr.ClientSecret) {
			return nil, common.ErrInvalidClient
		}
	} else if len(cli.GetSecret()) > 0 && tgr.ClientSecret != cli.GetSecret() {
		return nil, common.ErrInvalidClient
	}
	if tgr.RedirectURI != "" {
		if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
			return nil, err
		}
	}

	if gt == common.ClientCredentials && cli.IsPublic() == true {
		return nil, common.ErrInvalidClient
	}

	if gt == common.AuthorizationCode {
		ti, err := m.getAndDelAuthorizationCode(ctx, tgr)
		if err != nil {
			return nil, err
		}
		if err := m.validateCodeChallenge(ti, tgr.CodeVerifier); err != nil {
			return nil, err
		}
		tgr.UserID = ti.GetUserID()
		tgr.Scope = ti.GetScope()
		if exp := ti.GetAccessExpiresIn(); exp > 0 {
			tgr.AccessTokenExp = exp
		}
	}

	ti := model.NewToken()
	ti.SetClientID(tgr.ClientID)
	ti.SetUserID(tgr.UserID)
	ti.SetRedirectURI(tgr.RedirectURI)
	ti.SetScope(tgr.Scope)

	createAt := time.Now()
	ti.SetAccessCreateAt(createAt)

	// set access token expires
	gcfg := m.grantConfig(gt)
	aexp := gcfg.AccessTokenExp
	if exp := tgr.AccessTokenExp; exp > 0 {
		aexp = exp
	}
	ti.SetAccessExpiresIn(aexp)
	if gcfg.IsGenerateRefresh {
		ti.SetRefreshCreateAt(createAt)
		ti.SetRefreshExpiresIn(gcfg.RefreshTokenExp)
	}

	td := &common.GenerateBasic{
		Client:    cli,
		UserID:    tgr.UserID,
		CreateAt:  createAt,
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	av, rv, err := m.accessGenerate.Token(ctx, td, gcfg.IsGenerateRefresh)
	if err != nil {
		return nil, err
	}
	ti.SetAccess(av)

	if rv != "" {
		ti.SetRefresh(rv)
	}

	err = m.tokenStore.Create(ctx, ti)
	if err != nil {
		return nil, err
	}

	return ti, nil
}

// RefreshAccessToken refreshing an access token
func (m *Manager) RefreshAccessToken(ctx context.Context, tgr *common.TokenGenerateRequest) (common.TokenInfo, error) {
	ti, err := m.LoadRefreshToken(ctx, tgr.Refresh)
	if err != nil {
		return nil, err
	}

	cli, err := m.GetClient(ctx, ti.GetClientID())
	if err != nil {
		return nil, err
	}

	oldAccess, oldRefresh := ti.GetAccess(), ti.GetRefresh()

	td := &common.GenerateBasic{
		Client:    cli,
		UserID:    ti.GetUserID(),
		CreateAt:  time.Now(),
		TokenInfo: ti,
		Request:   tgr.Request,
	}

	rcfg := DefaultRefreshTokenCfg
	if v := m.rcfg; v != nil {
		rcfg = v
	}

	ti.SetAccessCreateAt(td.CreateAt)
	if v := rcfg.AccessTokenExp; v > 0 {
		ti.SetAccessExpiresIn(v)
	}

	if v := rcfg.RefreshTokenExp; v > 0 {
		ti.SetRefreshExpiresIn(v)
	}

	if rcfg.IsResetRefreshTime {
		ti.SetRefreshCreateAt(td.CreateAt)
	}

	if scope := tgr.Scope; scope != "" {
		ti.SetScope(scope)
	}

	tv, rv, err := m.accessGenerate.Token(ctx, td, rcfg.IsGenerateRefresh)
	if err != nil {
		return nil, err
	}

	ti.SetAccess(tv)
	if rv != "" {
		ti.SetRefresh(rv)
	}

	if err := m.tokenStore.Create(ctx, ti); err != nil {
		return nil, err
	}

	if rcfg.IsRemoveAccess {
		// remove the old access token
		if err := m.tokenStore.RemoveByAccess(ctx, oldAccess); err != nil {
			return nil, err
		}
	}

	if rcfg.IsRemoveRefreshing && rv != "" {
		// remove the old refresh token
		if err := m.tokenStore.RemoveByRefresh(ctx, oldRefresh); err != nil {
			return nil, err
		}
	}

	if rv == "" {
		ti.SetRefresh("")
		ti.SetRefreshCreateAt(time.Now())
		ti.SetRefreshExpiresIn(0)
	}

	return ti, nil
}

// RemoveAccessToken use the access token to delete the token information
func (m *Manager) RemoveAccessToken(ctx context.Context, access string) error {
	if access == "" {
		return common.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByAccess(ctx, access)
}

// RemoveRefreshToken use the refresh token to delete the token information
func (m *Manager) RemoveRefreshToken(ctx context.Context, refresh string) error {
	if refresh == "" {
		return common.ErrInvalidAccessToken
	}
	return m.tokenStore.RemoveByRefresh(ctx, refresh)
}

// LoadAccessToken according to the access token for corresponding token information
func (m *Manager) LoadAccessToken(ctx context.Context, access string) (common.TokenInfo, error) {
	if access == "" {
		return nil, common.ErrInvalidAccessToken
	}

	ct := time.Now()
	ti, err := m.tokenStore.GetByAccess(ctx, access)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetAccess() != access {
		return nil, common.ErrInvalidAccessToken
	} else if ti.GetRefresh() != "" && ti.GetRefreshExpiresIn() != 0 &&
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(ct) {
		return nil, common.ErrExpiredRefreshToken
	} else if ti.GetAccessExpiresIn() != 0 &&
		ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Before(ct) {
		return nil, common.ErrExpiredAccessToken
	}
	return ti, nil
}

// LoadRefreshToken according to the refresh token for corresponding token information
func (m *Manager) LoadRefreshToken(ctx context.Context, refresh string) (common.TokenInfo, error) {
	if refresh == "" {
		return nil, common.ErrInvalidRefreshToken
	}

	ti, err := m.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil {
		return nil, err
	} else if ti == nil || ti.GetRefresh() != refresh {
		return nil, common.ErrInvalidRefreshToken
	} else if ti.GetRefreshExpiresIn() != 0 && // refresh token set to not expire
		ti.GetRefreshCreateAt().Add(ti.GetRefreshExpiresIn()).Before(time.Now()) {
		return nil, common.ErrExpiredRefreshToken
	}
	return ti, nil
}
