package rbac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Run("TestNew_TokenSignKeyInvalid", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey: []byte(""),
			}
		)

		_, err := New(sets)
		assert.Error(t, err)
		assert.Equal(t, ErrorTokenSignKeyInvalid, err.Error())
	})

	t.Run("TestNew_RefreshTokenExpireTimeInvalid", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey:           []byte("gVoiG1fbXf65osbjfi33MZre"),
				TokenIssuer:            "lgcgo.com",
				PolicyFilePath:         "",
				AccessTokenExpireTime:  24 * time.Hour,
				RefreshTokenExpireTime: 12 * time.Hour,
			}
			err error
		)

		_, err = New(sets)

		assert.Error(t, err)
		assert.Equal(t, ErrorRefreshTokenExpireTimeInvalid, err.Error())
	})
}

func TestRefreshAuthorization(t *testing.T) {
	t.Run("TestRefreshAuthorization_ErrorTokenIssueTypeFail", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
				TokenIssuer:    "lgcgo.com",
				PolicyFilePath: "examples/policy.csv",
			}
			r     *Rbac
			token *Token
			err   error
		)

		r, _ = New(sets)

		token, _ = r.Authorization("uid001", "u1")

		_, err = r.RefreshAuthorization(token.AccessToken)

		assert.Error(t, err)
		assert.Equal(t, ErrorTokenIssueTypeInvalid, err.Error())
	})
}
