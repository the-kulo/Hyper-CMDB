package model

type Role struct {
	BaseModel

	Name   RoleName   `json:"name" gorm:"uniqueIndex;size:20;not null"`
	Desc   string     `json:"desc" gorm:"size:50;not null"`
	Status RoleStatus `json:"status" gorm:"default:1"`
	Level  RoleLevel  `json:"level" gorm:"not null;index"`
}

type RoleName string

const (
	RoleSuperAdmin   RoleName = "super_admin"   // 超级管理员
	RoleSystemAdmin  RoleName = "system_admin"  // 系统管理员
	RoleProjectAdmin RoleName = "project_admin" // 项目管理员
	RoleOpsEngineer  RoleName = "ops_engineer"  // 运维工程师
	RoleBusinessUser RoleName = "business_user" // 业务用户
	RoleAuditor      RoleName = "auditor"       // 审计员
)

type RoleStatus int

const (
	RoleStatusNormal RoleStatus = iota + 1
	RoleStatusDisabled
)

func (r RoleStatus) String() string {
	switch r {
	case RoleStatusNormal:
		return "正常"
	case RoleStatusDisabled:
		return "禁用"
	default:
		return "未知"
	}
}

type RoleLevel int

const (
	RoleLevelSuperAdmin   RoleLevel = 10
	RoleLevelSystemAdmin  RoleLevel = 8
	RoleLevelProjectAdmin RoleLevel = 6
	RoleLevelOpsEngineer  RoleLevel = 4
	RoleLevelBusinessUser RoleLevel = 2
	RoleLevelAuditor      RoleLevel = 1
)

func (r *Role) SetLevelByName() {
	levelMap := map[RoleName]RoleLevel{
		RoleSuperAdmin:   RoleLevelSuperAdmin,
		RoleSystemAdmin:  RoleLevelSystemAdmin,
		RoleProjectAdmin: RoleLevelProjectAdmin,
		RoleOpsEngineer:  RoleLevelOpsEngineer,
		RoleBusinessUser: RoleLevelBusinessUser,
		RoleAuditor:      RoleLevelAuditor,
	}

	if level, exists := levelMap[r.Name]; exists {
		r.Level = level
	}
}
