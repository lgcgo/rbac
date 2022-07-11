package rbac

var (
	// Rbac
	ErrorTokenSignKeyInvalid           = "token signkey invalid"
	ErrorRefreshTokenExpireTimeInvalid = "token refresh_token expiretime invalid"
	ErrorTokenIssueTypeInvalid         = "token issue type invalid"
	ErrorPolicyFilePathInvalid         = "policy file path invaild"

	// Jwt
	ErrorJwtSigningMethodInvaild = "token signing method invalid"
	ErrorJwtClaimsInvaild        = "token claim invaid"

	// Casbin
	ErrorCasbinEnforceInvaild = "casbin enforce invaild"
)
