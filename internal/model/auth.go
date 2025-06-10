package model

import "time"

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
	Role      RoleInfo  `json:"role"`
}

type UserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Avatar   string `json:"avatar"`
	Status   int    `json:"status"`
}

type RoleInfo struct {
	ID   uint     `json:"id"`
	Name RoleName `json:"name"`
}
