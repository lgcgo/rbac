package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRbac_VerifyRequest(t *testing.T) {
	var (
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		r   *Rbac
		err error
	)

	if r, err = New(sets); err != nil {
		assert.Fail(t, err.Error())
	}

	type args struct {
		uri    string
		method string
		role   string
	}
	tests := []struct {
		name    string
		r       *Rbac
		args    args
		wantErr bool
	}{
		{
			name: "Nonexistent Role Get User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "GET",
				role:   "noneRole",
			},
			wantErr: true,
		},
		{
			name: "Existing Role But Not Right Get User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "GET",
				role:   "userRole2",
			},
			wantErr: true,
		},
		{
			name: "Existing Role Has Right Get User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "GET",
				role:   "userRole1",
			},
			wantErr: false,
		},
		{
			name: "Existing Role Has Right Delete User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "DELETE",
				role:   "userRole1",
			},
			wantErr: false,
		},
		{
			name: "SuperAdmin Get User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "GET",
				role:   "root",
			},
			wantErr: false,
		},
		{
			name: "SuperAdmin Delete User",
			r:    r,
			args: args{
				uri:    "/user",
				method: "DELETE",
				role:   "root",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.r.VerifyRequest(tt.args.uri, tt.args.method, tt.args.role); (err != nil) != tt.wantErr {
				t.Errorf("VerifyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
