/*
 * License: https://github.com/lgcgo/rbac/LICENSE
 * Created Date: Wednesday, June 29th 2022, 11:56:33 pm
 * Author: jimmy
 *
 * Copyright (c) 2022 Author https://lgcgo.com
 */

package rbac

import (
	"bufio"
	"errors"
	"os"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

type Casbin struct {
	PolicyFilePath string
	Domain         string
	Enforcer       *casbin.Enforcer
	Adapter        persist.Adapter
}

// 从字符串初始化模型
var modelText = `
 [request_definition]
 r = sub, dom, obj, act
 
 [policy_definition]
 p = sub, dom, obj, act
 
 [role_definition]
 g = _, _, _
 
 [policy_effect]
 e = some(where (p.eft == allow))
 
 [matchers]
 m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act || r.sub == "root"
 `

var insCasbin = &Casbin{}

func NewCasbin(policyFilePath string) *Casbin {
	insCasbin.PolicyFilePath = policyFilePath
	return insCasbin
}

func (c *Casbin) Init() error {
	var (
		a   persist.Adapter
		e   *casbin.Enforcer // Casbin执行器
		m   model.Model      // Casbin认证模型
		err error
	)

	// 设置Adapter
	if c.Adapter == nil {
		if c.PolicyFilePath == "" {
			return errors.New(ErrorPolicyFilePathInvalid)
		}
		a = fileadapter.NewAdapter(c.PolicyFilePath)
		c.Adapter = a
	}
	// 使用字符串获取 Casbin模型
	if m, err = model.NewModelFromString(modelText); err != nil {
		return err
	}
	// 获取 Casbin执行器
	if e, err = casbin.NewEnforcer(m, a); err != nil {
		return err
	}
	c.Adapter = a
	c.Enforcer = e

	return nil
}

// 设置适配器
func (c *Casbin) SetAdapter(a persist.Adapter) {
	c.Adapter = a
}

// 设置域
func (c *Casbin) SetDomain(domain string) {
	c.Domain = domain
}

// 检测Policy
func (c *Casbin) VerifyUriPolicy(p *UriPolicy) error {
	var (
		err error
		ok  bool
	)

	ok, err = c.Enforcer.Enforce(p.Role, p.Domain, p.Path, p.Method)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(ErrorCasbinEnforceInvaild)
	}

	return nil
}

// 更新Policy.csv文件
func (c *Casbin) SaveAllPolicyCsv(ups []UriPolicy, rps []RolePolicy) error {
	var (
		filePath = c.PolicyFilePath
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

func (c *Casbin) Demo() {

}
