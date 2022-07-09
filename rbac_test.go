package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Run("TestNew_SettingTokenSignKeyEmptyFail", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey: []byte{},
			}
		)

		_, err := New(sets)

		assert.Error(t, err)
		assert.Equal(t, err.Error(), ErrorSettingTokenSignKeyInvalid)
	})

	t.Run("TestNew_ErrorPolicyAdapterEmptyFail", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
				TokenIssuer:    "lgcgo.com",
				PolicyFilePath: "",
			}
			err error
		)
		_, err = New(sets, "fali adapter")

		assert.Equal(t, ErrorPolicyAdapterInvalid, err.Error())
	})

	t.Run("TestNew_SettingPolicyFilePathEmptyFail", func(t *testing.T) {
		var (
			sets = Settings{
				TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
				TokenIssuer:    "lgcgo.com",
				PolicyFilePath: "",
			}
			err error
		)

		_, err = New(sets)

		assert.Error(t, err)
		assert.Equal(t, err.Error(), ErrorSettingPolicyFilePathInvalid)
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
			accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJpc3N1ZSIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NDMyNTcwLCJuYmYiOjE2NTczNDYxNzAsImlhdCI6MTY1NzM0NjE3MH0.oekFryKkVfBsPJDe-A6-Nph8jR0T2uS3_R4WUq2Kto0"
			r           *Rbac
			err         error
		)
		if r, err = New(sets); err != nil {
			panic(err)
		}
		_, err = r.RefreshAuthorization(accessToken)

		assert.Error(t, err)
		assert.Equal(t, ErrorTokenIssueTypeInvalid, err.Error())
	})
}
