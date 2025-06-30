package model

import (
	"time"

	"gorm.io/datatypes"
)

// 基础用户模型
type User struct {
	BaseModel
	Username    string         `json:"username" gorm:"uniqueIndex;size:10;not null"`
	Password    string         `json:"-" gorm:"size:80;not null"`
	Email       string         `json:"email" gorm:"uniqueIndex;size:50;not null"`
	Phone       string         `json:"phone" gorm:"uniqueIndex;size:15;not null"`
	Avatar      string         `json:"avatar" gorm:"size:255"`
	Status      UserStatus     `json:"status" gorm:"default:1"`
	LastLoginAt *time.Time     `json:"last_login_at"`
	LastLoginIP string         `json:"last_login_ip"`
	Profile     datatypes.JSON `json:"profile" `
	Roles       []Role         `json:"roles" gorm:"many2many:user_roles;"`
}

// 用户状态
type UserStatus int

const (
	UserStatusActive UserStatus = iota + 1
	UserStatusInactive
	UserStatusLocked
	UserStatusDeleted
)

func (s UserStatus) String() string {
	switch s {
	case UserStatusActive:
		return "Active"
	case UserStatusInactive:
		return "Inactive"
	case UserStatusLocked:
		return "Locked"
	case UserStatusDeleted:
		return "Deleted"
	default:
		return "Unknown"
	}
}
