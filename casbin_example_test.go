package rbac

func ExampleCasbin_SaveAllPolicyCsv() {
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

	if err = r.Casbin.SaveAllPolicyCsv(uriPolicys, rolePolicys); err != nil {
		panic(err)
	}

	// Output:
	//
}

// func ExampleCasbin_Demo() {
// 	var (
// 		sets = Settings{
// 			TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
// 			TokenIssuer:    "lgcgo.com",
// 			PolicyFilePath: "examples/policy.csv",
// 		}
// 		res [][]string
// 		r   *Rbac
// 	)
// 	r, _ = New(sets)
// 	r.Casbin.Init()
// 	// res = r.Casbin.Enforcer.GetAllSubjects()
// 	// res = r.Casbin.Enforcer.GetAllObjects()
// 	// res = r.Casbin.Enforcer.GetAllNamedActions("p")
// 	// res = r.Casbin.Enforcer.GetAllNamedObjects("p")
// 	res = r.Casbin.Enforcer.GetPermissionsForUser("role::u1")
// 	for _, v := range res {
// 		fmt.Println(v)
// 	}
// 	// fmt.Println(res)

// 	// Output:
// 	//
// }
