/*
 * License: https://github.com/lgcgo/rbac/LICENSE
 * Created Date: Wednesday, June 29th 2022, 11:56:33 pm
 * Author: jimmy
 *
 * Copyright (c) 2022 Author https://lgcgo.com
 */

package rbac

import (
	"errors"
	"time"

	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

type Rbac struct {
	settings      Settings
	policyAdapter persist.Adapter
}

// 设置项
type Settings struct {
	TokenSignKey           []byte        // 必填项，Jwt加密字符串，使用随机的字符串即可
	TokenIssuer            string        // 选填项，Jwt的签发者，如lgcgo.com
	PolicyFilePath         string        // 可选项，授权政策文件路径；当使用默认的adapter时为必填
	AccessTokenExpireTime  time.Duration // 可选项，access_token过期时间，默认24小时，
	RefreshTokenExpireTime time.Duration // 可选项，refresh_token过期时间，默认是access_token过期时间的3倍数
}

// 授权返回结构
type Token struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    uint
	RefreshToken string
}

func New(sets Settings, params ...interface{}) (*Rbac, error) {
	var (
		adapter  persist.Adapter
		duration time.Duration
		ok       bool
	)

	// 验证加密密钥
	if sets.TokenSignKey == nil || len(sets.TokenSignKey) == 0 {
		return nil, errors.New(ErrorSettingTokenSignKeyInvalid)
	}
	// 验证授权政策
	if len(params) > 0 {
		if adapter, ok = params[0].(persist.Adapter); !ok {
			return nil, errors.New(ErrorPolicyAdapterInvalid)
		}
	} else {
		if sets.PolicyFilePath == "" {
			return nil, errors.New(ErrorSettingPolicyFilePathInvalid)
		}
		adapter = fileadapter.NewAdapter(sets.PolicyFilePath)
	}
	// 设置access_token默认过期时间
	if sets.AccessTokenExpireTime == 0 {
		duration, _ = time.ParseDuration("24h")
		sets.AccessTokenExpireTime = duration
	}
	// 设置默认refresh_token默认过期时间
	if sets.RefreshTokenExpireTime == 0 {
		sets.RefreshTokenExpireTime = sets.AccessTokenExpireTime * 3
	}

	return &Rbac{
		sets,
		adapter,
	}, nil
}

// 签发授权（oauth2密码模式）
func (r *Rbac) Authorization(subject, role string) (*Token, error) {
	var (
		sets         = r.settings
		jwt          = NewJwt(sets.TokenSignKey, sets.TokenIssuer)
		currentTime  = time.Now()
		err          error
		accessToken  string
		tokenType    string
		refreshToken string
		expiresIn    float64
	)

	// 实例化签名
	iClaims := &IssueClaims{
		Subject: subject,
		Role:    role,
	}
	// 制作 accessToken
	iClaims.Type = "grant"
	if accessToken, err = jwt.IssueToken(iClaims, sets.AccessTokenExpireTime); err != nil {
		return nil, err
	}
	// 制作 refreshToken
	iClaims.Type = "renew"
	if refreshToken, err = jwt.IssueToken(iClaims, sets.RefreshTokenExpireTime); err != nil {
		return nil, err
	}
	// 获取过期秒数
	expiresIn = currentTime.Add(sets.AccessTokenExpireTime).Sub(currentTime).Seconds()
	// 支持Bearer签发方案(Header Authorization: Bearer <token>)
	tokenType = "Bearer"

	// 组装返回数据
	return &Token{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		ExpiresIn:    uint(expiresIn),
	}, nil
}

// 刷新授权
func (r *Rbac) RefreshAuthorization(ticket string) (*Token, error) {
	var (
		sets   = r.settings
		jwt    = NewJwt(sets.TokenSignKey, sets.TokenIssuer)
		claims map[string]interface{}
		err    error
	)

	// 解析token
	if claims, err = jwt.ParseToken(ticket); err != nil {
		return nil, err
	}
	// 校验签发类型
	if claims["ist"] != "renew" {
		return nil, errors.New(ErrorTokenIssueTypeInvalid)
	}

	return r.Authorization(claims["sub"].(string), claims["isr"].(string))
}

// 验证Token
func (r *Rbac) VerifyToken(ticket string) (map[string]interface{}, error) {
	var (
		sets   = r.settings
		jwt    = NewJwt(sets.TokenSignKey, sets.TokenIssuer)
		claims map[string]interface{}
		err    error
	)

	// 解析Token
	if claims, err = jwt.ParseToken(ticket); err != nil {
		return nil, err
	}
	// 非法动作签名
	if claims["ist"] != "grant" {
		return nil, errors.New(ErrorTokenIssueTypeInvalid)
	}

	return claims, nil
}

// 验证角色请求
func (r *Rbac) VerifyRequest(uri, method, role string) error {
	var (
		casbin *Casbin
		err    error
	)

	if casbin, err = NewCasbin(r.policyAdapter); err != nil {
		return err
	}

	return casbin.VerifyUriPolicy(&UriPolicy{
		Subject: role,
		Object:  uri,
		Action:  method,
	})
}
