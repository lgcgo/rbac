/*
 * License: https://github.com/lgcgo/rbac/LICENSE
 * Created Date: Thursday, June 30th 2022, 12:02:17 am
 * Author: jimmy
 *
 * Copyright (c) 2022 Author https://lgcgo.com
 */

package rbac

import (
	"errors"
	"time"

	pkg "github.com/golang-jwt/jwt/v4"
)

type Jwt struct {
	signKey []byte // 加密密钥
	issuer  string // 签发者
}

// 声明格式
// RegisteredClaims 包含了JWT给出的7个官方字段
// - iss (issuer)：发布者，通常填域名即可
// - sub (subject)：主题，
// - iat (Issued At)：生成签名的时间
// - exp (expiration time)：签名过期时间
// - aud (audience)：观众，相当于接受者
// - nbf (Not Before)：生效时间
// - jti (JWT ID)：编号
type Claims struct {
	IssueType string `json:"ist"` // 签发类型, grant=授予,renew=刷新
	IssueRole string `json:"isr"` // 签发角色, 签发的角色名称（允许多角色）
	pkg.RegisteredClaims
}

// 签发字段
type IssueClaims struct {
	Type     string   // 签发类型，这里 grant=授权, renew=刷新
	Role     string   // 签发角色，相同角色具备相同的权限
	Subject  string   // 签发主题，一般用使用用户的唯一标识
	Audience []string // 签发授众，例如指定的浏览器、应用标识等
}

var insJwt = &Jwt{}

func NewJwt() *Jwt {
	return insJwt
}

// 初始化
func (j *Jwt) Init(signKey []byte, issuer string) {
	j.signKey = signKey
	j.issuer = issuer
}

// 签发Token
func (j *Jwt) IssueToken(iClaims *IssueClaims, expireTime time.Duration) (string, error) {
	var (
		token  *pkg.Token
		ticket string
		err    error
	)

	// 创建签名
	claims := &Claims{
		iClaims.Type,
		iClaims.Role,
		pkg.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   iClaims.Subject,
			Audience:  iClaims.Audience,
			ExpiresAt: pkg.NewNumericDate(time.Now().Add(expireTime)),
			NotBefore: pkg.NewNumericDate(time.Now()),
			IssuedAt:  pkg.NewNumericDate(time.Now()),
		},
	}
	// 生成token
	token = pkg.NewWithClaims(pkg.SigningMethodHS256, claims)
	if ticket, err = token.SignedString(j.signKey); err != nil {
		return "", err
	}

	return ticket, nil
}

// 解析Token
func (j *Jwt) ParseToken(ticket string) (map[string]interface{}, error) {
	var (
		token  *pkg.Token
		claims map[string]interface{}
		err    error
		ok     bool
	)

	// 解析Token对象
	if token, err = pkg.Parse(ticket, func(token *pkg.Token) (interface{}, error) {
		if _, ok = token.Method.(*pkg.SigningMethodHMAC); !ok {
			return nil, errors.New(ErrorJwtSigningMethodInvaild)
		}
		return j.signKey, nil
	}); err != nil {
		return nil, err
	}
	// 验证签名
	if claims, ok = token.Claims.(pkg.MapClaims); !ok || !token.Valid {
		return nil, errors.New(ErrorJwtClaimsInvaild)
	}

	return claims, nil
}
