[![OSCS Status](https://www.oscs1024.com/platform/badge/lgcgo/rbac.svg?size=small)](https://www.oscs1024.com/project/lgcgo/rbac?ref=badge_small)

## 介绍
一个Go语言基于Casbin认证、JWT授权的 [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control) 基于角色的访问控制完整实现。

## 特性
- 支持RefreshToken平滑刷新
- Token黑名单（待实现）

## 使用示例
**签发授权**
```Go
import (
    "github.com/lgcgo/rbac"
)

var (
    settings = rbac.Settings{
        TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
        TokenIssuer:    "lgcgo.com",
        PolicyFilePath: "examples/policy.csv",
    }
)

func main(){
    // 实例化
    if r, err :=rbac.New(settings); err != nil {
        panic(err)
    }
    // 签发授权
    if out, err = r.Authorization("uid001", "subAdmin"); err != nil {
        panic(err)
    }
    // 格式化打印
    outJson, _ := json.MarshalIndent(out, "", "   ")
    fmt.Println(string(outJson))
}
```
打印结果
```Shell
{
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJncmFudCIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NDM3NTk5LCJuYmYiOjE2NTczNTExOTksImlhdCI6MTY1NzM1MTE5OX0.CBzE0bn9mKYqYIDNVgujnHTFUM9uTM54mwRwpzjcDFA",
    "tokenType": "Bearer",
    "expiresIn": 86400,
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3QiOiJyZW5ldyIsImlzciI6InN1YkFkbWluIiwiaXNzIjoibGdjZ28uY29tIiwic3ViIjoidWlkMDAxIiwiZXhwIjoxNjU3NjEwMzk5LCJuYmYiOjE2NTczNTExOTksImlhdCI6MTY1NzM1MTE5OX0.Pozlza3jeWk6Kd2C6ZebiZcD3nZoMRfQdJV9alEzfj0"
}
```
返回的数据结构，参考了Oauth2授权模式，实际上已经满足了密码模式条件，只是登录认证需要而且**应该**由应用系统本身实现。

**刷新授权**
```Go
// 实例化
if r, err = rbac.New(settings); err != nil {
    panic(err)
}
refreshToken := "×××.×××.×××"
r.RefreshAuthorization(refreshToken)
```
平滑的token刷新机制，能有效提升用户体验，这也是为为什么参考Oauth2授权模式的原因；如果你对系统安全有极致的要求，可以在当前步骤中添加使用 `refreshToken` 的条件。

**验证Token**
```Go
// 实例化
if r, err = rbac.New(settings); err != nil {
    panic(err)
}
accessToken := "×××.×××.×××"
claims, err := r.VerifyToken(accessToken)
```
该接口通常在系统的中间件中使用，claims中 `应该` 包含用户唯一ID `sub` 以及用户角色名称 `isr` ，可以在该步骤中初始化用户信息（从缓存/数据库中读取用户数据）。

**验证请求**
```Go
// 实例化
if r, err = rbac.New(settings); err != nil {
    panic(err)
}

path := "/user"
method := "GET"
role := claims["isr"].(string)
// 验证请求
r.VerifyRequest(path, method, role)
```
该接口通常在验证Token后使用，底层调用Casbin进行权限认证，它只对签发角色 `isr` 负责，即相同的角色对同一个资源有相同的权限。

## 配置项
项目 | 必填 | 说明 | 示例
--- | :---: | --- | --- 
TokenSignKey | 否 | Jwt加密字符串，使用随机的字符串即可 | `[]byte("abc123")`
TokenIssuer  | 否 | Jwt的签发者，如lgcgo.com | `"lgcgo.com"`
PolicyFilePath | 否 | 授权政策文件路径；当使用默认的policy adapter时为必填 | `"config/policy.csv"`
AccessTokenExpireTime | 否 | accessToken过期时间，默认24小时 | `24 * time.Hour`
RefreshTokenExpireTime | 否 | refreshToken过期时间，默认是accessToken过期时间的3倍数 | `24 * time.Hour`

## Policy的储存
默认使用Casbin内置的 `file adapter` ，在初始化设置Setting中指定`PolicyFilePath` 即可。

**更新policy.csv文件**
```Go
import (
    "github.com/lgcgo/rbac"
)

var (
    uriPolicys = []rbac.UriPolicy{
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
    rolePolicys = []rbac.RolePolicy{
        {
            ParentRole: "superAdmin",
            Role:       "u1",
        },
    }
    sets = rbac.Settings{
        TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
        TokenIssuer:    "lgcgo.com",
        PolicyFilePath: "examples/policy.csv",
    }
    r   *rbac.Rbac
    err error
)

func main() {
    if r, err = rbac.New(sets); err != nil {
        panic(err)
    }

    if err = r.SavePolicyCsv(uriPolicys, rolePolicys); err != nil {
        panic(err)
    }
}
```
`SavePolicyCsv` 仅支持使用默认的policy适配器。请注意每次调用时，都是覆盖重写整个csv文件，也就要求传入完整的 `[]RuiPolicy` 和 `[]RolePolicy`。
<hr>
可以在这里找到更多的适配器[Casbin适配器](https://casbin.org/docs/zh-CN/adapters)。

**使用fs.Fs adapter示例**
```Go
import (
    casbinfsadapter "github.com/naucon/casbin-fs-adapter"
    "github.com/lgcgo/rbac"
)

var settings = Settings{
    TokenSignKey:   []byte("gVoiG1fbXf65osbjfi33MZre"),
    TokenIssuer:    "lgcgo.com",
    PolicyFilePath: "examples/policy.csv",
}

func main(){
    // 实例化第三方adapter
    fsys := os.DirFS("examples/config/")
    adapter := casbinfsadapter.NewAdapter(fsys, "policy.csv")
    
    // 实例化
    r, err :=rbac.New(settings)
    // 设置适配器
    r.Casbin.SetAdapter(adapter)
    // ...
}
```
一般情况下不建议使用orm或sql的内置适配器，原因一是效率不如内置的适配器，二是非关系型数据放sql里面怪别扭的。

## 认证中间件
**GoFrame示例**
```Go
var settings = rbac.Setting{
    // ...
}
func Authentication(r *ghttp.Request) {
    if obj, err :=rbac.New(settings); err != nil {
        panic(err)
    }
    // Header传值 Authorization: Bearer <token>
    if r.Header.Get("Authorization") == "" {
        panic("headers authorization not exists")
    }
    strArr = strings.SplitN(r.Header.Get("Authorization"), " ", 2)
    
    // 支持Bearer方案
    if strArr[0] != "Bearer" {
        panic("authorization scheme not support")
    }
    
    // 获取Token票据
    tokenTicket := strArr[1]
    if claims, err := obj.VerifyToken(tokenTicket); err != nil {
    	panic("token invalid")
    }
    
    // 从声明中获取用户角色
    role := claims["isr"].(string)
    
    // 验证角色的请求权限
    if err = obj.VerifyRequest(path, method, role); err != nil {
        panic("deny the request")
    }

    // 从声明中获取用户唯一ID
    // uid = claims["sub"].(string)
    // 用uid做些什么

    r.Middleware.Next()
}
```

## 版权声明
Under the [Apache2.0](https://github.com/logcgo/rbac/LICENSE)

## 特别致谢
- Casbin 开源项目 https://github.com/casbin/casbin
- GolangJwt 开源项目 https://github.com/golang-jwt/jwt
- Oauth0 Jwt https://jwt.io/

## 扩展阅读
- [理解Oauth2-阮一峰](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)
- [Casbin 超级管理员](https://casbin.org/docs/zh-CN/superadmin)
