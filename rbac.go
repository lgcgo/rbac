/*
 * Created Date: Wednesday, June 29th 2022, 11:56:33 pm
 * Author: jimmy.liu
 *
 * License: https://github.com/lgcgo/rbac/LICENSE
 * Copyright (c) 2022 Author https://lgcgo.com
 */

package rbac

import (
	"bufio"
	"errors"
	"os"
	"time"
)

type Rbac struct {
	settings Settings
	Jwt      *Jwt
	Casbin   *Casbin
}

// 设置项
type Settings struct {
	PolicyFilePath         string        // 可选项，授权政策文件路径；当使用默认的adapter时为必填
	TokenSignKey           []byte        // 必填项，Jwt加密字符串，使用随机的字符串即可
	TokenIssuer            string        // 选填项，Jwt的签发者，如lgcgo.com
	AccessTokenExpireTime  time.Duration // 可选项，access_token过期时间，默认24小时
	RefreshTokenExpireTime time.Duration // 可选项，refresh_token过期时间，默认是access_token过期时间的3倍数
}

// 授权返回结构
type Token struct {
	AccessToken  string `json:"accessToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    uint   `json:"expiresIn"`
	RefreshToken string `json:"refreshToken"`
}

var insRabc = &Rbac{}

func New(sets Settings) (*Rbac, error) {
	var (
		duration time.Duration
	)

	// 验证加密密钥
	if sets.TokenSignKey == nil || len(sets.TokenSignKey) == 0 {
		return nil, errors.New(ErrorTokenSignKeyInvalid)
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
	// refresh_token过期时间必须大于access_token过期时间
	if sets.AccessTokenExpireTime >= sets.RefreshTokenExpireTime {
		return nil, errors.New(ErrorRefreshTokenExpireTimeInvalid)
	}

	insRabc.settings = sets
	insRabc.Jwt = NewJwt(sets.TokenSignKey, sets.TokenIssuer)
	insRabc.Casbin = NewCasbin(sets.PolicyFilePath)

	return insRabc, nil
}

// 签发授权（oauth2密码模式）
func (r *Rbac) Authorization(subject, role string) (*Token, error) {
	var (
		sets         = r.settings
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
	if accessToken, err = r.Jwt.IssueToken(iClaims, sets.AccessTokenExpireTime); err != nil {
		return nil, err
	}
	// 制作 refreshToken
	iClaims.Type = "renew"
	if refreshToken, err = r.Jwt.IssueToken(iClaims, sets.RefreshTokenExpireTime); err != nil {
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
		claims map[string]interface{}
		err    error
	)

	// 解析token
	if claims, err = r.Jwt.ParseToken(ticket); err != nil {
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
		claims map[string]interface{}
		err    error
	)

	// 解析Token
	if claims, err = r.Jwt.ParseToken(ticket); err != nil {
		return nil, errors.New("token parse fail")
	}
	// 非法动作签名
	if claims["ist"] != "grant" {
		return nil, errors.New(ErrorTokenIssueTypeInvalid)
	}

	return claims, nil
}

// 验证角色请求
func (r *Rbac) VerifyRequest(path, method, role string) error {
	var (
		err error
	)

	// 初始化Casbin组件
	if err = r.Casbin.Init(); err != nil {
		return err
	}

	return r.Casbin.VerifyUriPolicy(&UriPolicy{
		role,
		path,
		method,
	})
}

// 更新Policy.csv文件
func (r *Rbac) SavePolicyCsv(ups []UriPolicy, rps []RolePolicy) error {
	var (
		filePath = r.settings.PolicyFilePath
		file     *os.File
		writer   *bufio.Writer
		err      error
	)

	if filePath == "" {
		return errors.New(ErrorPolicyFilePathInvalid)
	}
	// 获取文件句柄
	file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入文件
	writer = bufio.NewWriter(file)
	for _, v := range ups {
		writer.WriteString(v.FormatLine())
		writer.WriteString("\n")
	}
	for _, v := range rps {
		writer.WriteString(v.FormatLine())
		writer.WriteString("\n")
	}
	writer.Flush()

	return nil
}
