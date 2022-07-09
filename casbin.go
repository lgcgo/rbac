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

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

type Casbin struct {
	E *casbin.Enforcer
	A persist.Adapter
}

// 从字符串初始化模型
var modelText = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root"
`

func NewCasbin(a persist.Adapter) (*Casbin, error) {
	var (
		e   *casbin.Enforcer // Casbin执行器
		m   model.Model      // Casbin认证模型
		err error
	)

	// 使用字符串获取 Casbin模型
	if m, err = model.NewModelFromString(modelText); err != nil {
		return nil, err
	}
	// 获取 Casbin执行器
	if e, err = casbin.NewEnforcer(m, a); err != nil {
		return nil, err
	}

	return &Casbin{e, a}, nil
}

// 检测Policy
func (c *Casbin) VerifyUriPolicy(p *UriPolicy) error {
	var (
		err error
		ok  bool
	)

	if ok, err = c.E.Enforce(p.Subject, p.Object, p.Action); err != nil {
		return err
	}
	if !ok {
		return errors.New(ErrorNotRightRequest)
	}

	return nil
}
