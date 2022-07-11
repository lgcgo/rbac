package rbac

import (
	"encoding/json"
	"fmt"
)

func ExampleRbac_Authorization() {
	var (
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		r   *Rbac
		out *Token
		err error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}
	if out, err = r.Authorization("uid001", "subAdmin"); err != nil {
		panic(err)
	}
	outJson, err := json.MarshalIndent(out, "", "	")

	fmt.Println(string(outJson))

	// Output:
	// {
	// 	"AccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJncmFudCIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NDM1MzM0LCJuYmYiOjE2NTczNDg5MzQsImlhdCI6MTY1NzM0ODkzNH0.KfU0WgfT33v_5-HqqCryPCRC512dV2CTQ_uXCh5dJMM",
	// 	"TokenType": "Bearer",
	// 	"ExpiresIn": 86400,
	// 	"RefreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJyZW5ldyIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NjA4MTM0LCJuYmYiOjE2NTczNDg5MzQsImlhdCI6MTY1NzM0ODkzNH0.cd2-AplZwnu4CbhAZvSwRdWYESWurHTZlbXMSDta4wA"
	// }
}

func ExampleRbac_RefreshAuthorization() {
	var (
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		r     *Rbac
		token *Token
		out   *Token
		err   error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}
	if token, err = r.Authorization("uid001", "subAdmin"); err != nil {
		panic(err)
	}
	if out, err = r.RefreshAuthorization(token.RefreshToken); err != nil {
		panic(err)
	}
	outJson, err := json.MarshalIndent(out, "", "	")

	fmt.Println(string(outJson))

	// Output:
	// {
	// 	"accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJncmFudCIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NTk2NzM2LCJuYmYiOjE2NTc1MTAzMzYsImlhdCI6MTY1NzUxMDMzNn0.jtcnM1Gvcs3XQFl7xdDU7-qnnL90RyhfljAqKE_DmsA",
	// 	"tokenType": "Bearer",
	// 	"expiresIn": 86400,
	// 	"refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJyZW5ldyIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NzY5NTM2LCJuYmYiOjE2NTc1MTAzMzYsImlhdCI6MTY1NzUxMDMzNn0.xFpO99WrCxmrrvi6rlDy2DdAFdT6-DkdMWaA-QXIQsU"
	// }
}

func ExampleRbac_VerifyToken() {
	var (
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		r     *Rbac
		token *Token
		out   map[string]interface{}
		err   error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}
	if token, err = r.Authorization("uid001", "subAdmin"); err != nil {
		panic(err)
	}
	if out, err = r.VerifyToken(token.AccessToken); err != nil {
		panic(err)
	}
	outJson, err := json.MarshalIndent(out, "", "	")

	fmt.Println(string(outJson))

	// Output:
	// {
	// 	"exp": 1657596869,
	// 	"iat": 1657510469,
	// 	"isr": "subAdmin",
	// 	"iss": "lgcgo.com",
	// 	"ist": "grant",
	// 	"nbf": 1657510469,
	// 	"sub": "uid001"
	// }
}

func ExampleRbac_SavePolicyCsv() {
	var (
		uriPolicys = []UriPolicy{
			{
				Role:   "u1",
				Path:   "/user",
				Method: "GET",
			},
			{
				Role:   "u1",
				Path:   "/user",
				Method: "PUT",
			},
			{
				Role:   "u1",
				Path:   "/user",
				Method: "DELETE",
			},
			{
				Role:   "u1",
				Path:   "/users",
				Method: "GET",
			},
		}
		rolePolicys = []RolePolicy{
			{
				ParentRole: "superAdmin",
				Role:       "u1",
			},
		}
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		r   *Rbac
		err error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}

	if err = r.SavePolicyCsv(uriPolicys, rolePolicys); err != nil {
		panic(err)
	}

	// Output:
	//

}
