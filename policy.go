/*
 * License: https://github.com/lgcgo/rbac/LICENSE
 * Created Date: Wednesday, June 29th 2022, 11:56:33 pm
 * Author: jimmy
 *
 * Copyright (c) 2022 Author https://lgcgo.com
 */

package rbac

import (
	"strings"
)

// 授权政策接口
type IPolicy interface {
	FormatLine() string // 格式化行字符串
}

// 资源访问政策
type UriPolicy struct {
	Subject string // 代表用户角色
	Object  string // 代表请求路径
	Action  string // 代表请求方法
}

// 角色关系政策
type RolePolicy struct {
	ParentSubject string // 父级角色名称
	Subject       string // 角色名称
}

// 资源访问政策，实现格式化行字符串
func (u *UriPolicy) FormatLine() string {
	var (
		strArr []string
	)

	strArr = append(strArr, "p")
	strArr = append(strArr, u.Subject)
	strArr = append(strArr, u.Object)
	strArr = append(strArr, u.Action)

	return strings.Join(strArr, ", ")
}

// 角色关系政策，实现格式化行字符串
func (r *RolePolicy) FormatLine() string {
	var (
		strArr []string
	)

	strArr = append(strArr, "g")
	strArr = append(strArr, r.ParentSubject)
	strArr = append(strArr, r.Subject)

	return strings.Join(strArr, ", ")
}
