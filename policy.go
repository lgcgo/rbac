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
	Role   string // 用户角色
	Path   string // 资源路径
	Method string // 请求方法
}

// 角色关系政策
type RolePolicy struct {
	ParentRole string // 父级角色名称
	Role       string // 角色名称
}

// 资源访问政策，实现格式化行字符串
func (u *UriPolicy) FormatLine() string {
	var (
		strArr []string
	)

	strArr = append(strArr, "p")
	strArr = append(strArr, "role::"+u.Role)
	strArr = append(strArr, u.Path)
	strArr = append(strArr, u.Method)

	return strings.Join(strArr, ", ")
}

// 角色关系政策，实现格式化行字符串
func (r *RolePolicy) FormatLine() string {
	var (
		strArr []string
	)

	strArr = append(strArr, "g")
	strArr = append(strArr, "role::"+r.ParentRole)
	strArr = append(strArr, "role::"+r.Role)

	return strings.Join(strArr, ", ")
}
