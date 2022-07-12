package rbac

func ExampleCasbin_SaveAllPolicyCsv() {
	var (
		uriPolicys = []UriPolicy{
			{
				Domain: "manager",
				Role:   "admin1",
				Path:   "/user",
				Method: "POST",
			},
			{
				Domain: "manager",
				Role:   "admin1",
				Path:   "/user",
				Method: "GET",
			},
			{
				Domain: "manager",
				Role:   "admin1",
				Path:   "/user",
				Method: "PUT",
			},
			{
				Domain: "manager",
				Role:   "admin1",
				Path:   "/user",
				Method: "DELETE",
			},
			{
				Domain: "manager",
				Role:   "admin1",
				Path:   "/users",
				Method: "GET",
			},
			{
				Domain: "www",
				Role:   "admin1",
				Path:   "/article",
				Method: "GET",
			},
			{
				Domain: "www",
				Role:   "userGroup1",
				Path:   "/article",
				Method: "GET",
			},
		}
		rolePolicys = []RolePolicy{
			{
				Role:   "admin1",
				Domain: "manager",
			},
			{
				ParentRole: "admin1",
				Role:       "admin2",
				Domain:     "manager",
			},
			{
				ParentRole: "admin1",
				Role:       "userGroup1",
				Domain:     "www",
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
// 	// res = r.Casbin.Enforcer.GetAllRoles()
// 	// res = r.Casbin.Enforcer.GetPolicy() // 只会获取p类型政策，不会获取角色关系
// 	// res, _ = r.Casbin.Enforcer.GetUsersForRole("role::admin2", "manager") // 必须指定domain，只能获取直属父级
// 	// res, _ = r.Casbin.Enforcer.GetAllDomains()
// 	// res, _ = r.Casbin.Enforcer.GetDomainsForUser("root")

// 	res = r.Casbin.Enforcer.GetPermissionsForUser("role::admin1")
// 	for _, v := range res {
// 		fmt.Println(v)
// 	}
// 	fmt.Println(res)

// 	// Output:
// 	//
// }
