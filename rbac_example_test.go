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
		refreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJyZW5ldyIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NjA4MTM0LCJuYmYiOjE2NTczNDg5MzQsImlhdCI6MTY1NzM0ODkzNH0.cd2-AplZwnu4CbhAZvSwRdWYESWurHTZlbXMSDta4wA"
		r            *Rbac
		out          *Token
		err          error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}
	if out, err = r.RefreshAuthorization(refreshToken); err != nil {
		panic(err)
	}
	outJson, err := json.MarshalIndent(out, "", "	")

	fmt.Println(string(outJson))

	// Output:
	// {
	// 	"AccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJncmFudCIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NDM1Mzk4LCJuYmYiOjE2NTczNDg5OTgsImlhdCI6MTY1NzM0ODk5OH0.xWcm_eGeyikb-1TXoYZmJmkWGuza_URX1HsA2GUePz4",
	// 	"TokenType": "Bearer",
	// 	"ExpiresIn": 86400,
	// 	"RefreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJyZW5ldyIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NjA4MTk4LCJuYmYiOjE2NTczNDg5OTgsImlhdCI6MTY1NzM0ODk5OH0.gLObT_ANnXTHK3xAqM9KN27H1zRXrPdp0boX6CuuObU"
	// }
}

func ExampleRbac_VerifyToken() {
	var (
		sets = Settings{
			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
			TokenIssuer:    "lgcgo.com",
			PolicyFilePath: "examples/policy.csv",
		}
		accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJncmFudCIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NDM1Mzk4LCJuYmYiOjE2NTczNDg5OTgsImlhdCI6MTY1NzM0ODk5OH0.xWcm_eGeyikb-1TXoYZmJmkWGuza_URX1HsA2GUePz4"
		r           *Rbac
		out         map[string]interface{}
		err         error
	)

	if r, err = New(sets); err != nil {
		panic(err)
	}
	if out, err = r.VerifyToken(accessToken); err != nil {
		panic(err)
	}
	outJson, err := json.MarshalIndent(out, "", "	")

	fmt.Println(string(outJson))

	// Output:
	// {
	// 	"exp": 1657435398,
	// 	"iat": 1657348998,
	// 	"isr": "subAdmin",
	// 	"iss": "lgcgo.com",
	// 	"ist": "grant",
	// 	"nbf": 1657348998,
	// 	"sub": "uid001"
	// }
}
