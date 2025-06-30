package model

import (
	"time"
)

// JWTBlacklist JWT黑名单模型
type JWTBlacklist struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	TokenID   string    `gorm:"uniqueIndex;size:255;not null" json:"token_id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	TokenType string    `gorm:"type:enum('access','refresh');not null" json:"token_type"`
	ExpiredAt time.Time `gorm:"index;not null" json:"expired_at"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// TableName 指定表名
func (JWTBlacklist) TableName() string {
	return "jwt_blacklist"
}

// JWTLog JWT日志模型
type JWTLog struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       *uint     `gorm:"index" json:"user_id"`
	Action       string    `gorm:"type:enum('generate','validate','refresh','revoke');not null;index" json:"action"`
	TokenType    string    `gorm:"type:enum('access','refresh');not null" json:"token_type"`
	IPAddress    string    `gorm:"size:45" json:"ip_address"`
	UserAgent    string    `gorm:"type:text" json:"user_agent"`
	Success      bool      `gorm:"not null" json:"success"`
	ErrorMessage string    `gorm:"type:text" json:"error_message"`
	CreatedAt    time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName 指定表名
func (JWTLog) TableName() string {
	return "jwt_logs"
}

// JWTTokenPair JWT令牌对
type JWTTokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// BlacklistItem 黑名单项（用于异步处理）
type BlacklistItem struct {
	TokenID   string
	UserID    uint
	TokenType string
	ExpiredAt time.Time
	CreatedAt time.Time
}

// JWTLogItem JWT日志项（用于异步处理）
type JWTLogItem struct {
	UserID       *uint
	Action       string
	TokenType    string
	IPAddress    string
	UserAgent    string
	Success      bool
	ErrorMessage string
	CreatedAt    time.Time
}

// BlacklistStats 黑名单统计信息
type BlacklistStats struct {
	Total         int64 `json:"total"`          // 总数
	Active        int64 `json:"active"`         // 活跃数（未过期）
	Expired       int64 `json:"expired"`        // 过期数
	AccessTokens  int64 `json:"access_tokens"`  // 访问令牌数
	RefreshTokens int64 `json:"refresh_tokens"` // 刷新令牌数
}

// LogStats 日志统计信息
type LogStats struct {
	Total    int64            `json:"total"`     // 总数
	Success  int64            `json:"success"`   // 成功数
	Failed   int64            `json:"failed"`    // 失败数
	Today    int64            `json:"today"`     // 今日数量
	ByAction map[string]int64 `json:"by_action"` // 按操作类型统计
}

// UserActivity 用户活动统计
type UserActivity struct {
	UserID        uint      `json:"user_id"`
	ActivityCount int64     `json:"activity_count"`
	LastActivity  time.Time `json:"last_activity"`
}