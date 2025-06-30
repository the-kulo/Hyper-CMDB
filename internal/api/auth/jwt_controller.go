package auth

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"h-cmdb/internal/middleware"
	"h-cmdb/internal/model"
	"h-cmdb/internal/response"
	"h-cmdb/internal/service"
)

// JWTController JWT控制器
type JWTController struct {
	jwtService  service.JWTService
	userService service.UserService // 用户服务，用于验证用户凭据
}

// NewJWTController 创建JWT控制器
func NewJWTController(jwtService service.JWTService, userService service.UserService) *JWTController {
	return &JWTController{
		jwtService:  jwtService,
		userService: userService,
	}
}

// Login 用户登录
// @Summary 用户登录
// @Description 用户登录获取JWT令牌
// @Tags 认证
// @Accept json
// @Produce json
// @Param request body model.LoginRequest true "登录请求"
// @Success 200 {object} response.Response{data=model.LoginResponse} "登录成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 401 {object} response.Response "用户名或密码错误"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/login [post]
func (ctrl *JWTController) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请求参数错误: "+err.Error())
		return
	}

	// 验证用户凭据
	user, err := ctrl.userService.ValidateCredentials(req.Username, req.Password)
	if err != nil {
		response.Unauthorized(c, "用户名或密码错误: "+err.Error())
		return
	}

	// 获取客户端信息
	ipAddress, userAgent := middleware.GetClientInfo(c)

	// 生成JWT令牌对
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	tokenPair, err := ctrl.jwtService.GenerateTokenPair(ctx, uint(user.ID), userAgent, ipAddress)
	if err != nil {
		response.InternalServerError(c, "生成令牌失败: "+err.Error())
		return
	}

	// 获取用户主要角色（取权限级别最高的角色）
	var primaryRole *model.Role
	if len(user.Roles) > 0 {
		primaryRole = &user.Roles[0]
		for _, role := range user.Roles {
			if role.Level > primaryRole.Level {
				primaryRole = &role
			}
		}
	}

	// 构造响应
	loginResp := model.LoginResponse{
		Token:     tokenPair.AccessToken,
		ExpiresAt: tokenPair.ExpiresAt,
		User: model.UserInfo{
			ID:       uint(user.ID),
			Username: user.Username,
			Avatar:   user.Avatar,
			Status:   int(user.Status),
		},
	}

	// 设置角色信息（如果存在）
	if primaryRole != nil {
		loginResp.Role = model.RoleInfo{
			ID:   uint(primaryRole.ID),
			Name: primaryRole.Name,
		}
	} else {
		// 如果用户没有角色，设置默认值
		loginResp.Role = model.RoleInfo{
			ID:   0,
			Name: model.RoleBusinessUser, // 默认为业务用户
		}
	}

	// 设置刷新令牌到Cookie（可选）
	c.SetCookie(
		"refresh_token",
		tokenPair.RefreshToken,
		int(time.Until(tokenPair.ExpiresAt).Seconds()),
		"/",
		"",
		false, // secure
		true,  // httpOnly
	)

	response.Success(c, "登录成功", loginResp)
}

// RefreshToken 刷新令牌
// @Summary 刷新令牌
// @Description 使用刷新令牌获取新的访问令牌
// @Tags 认证
// @Accept json
// @Produce json
// @Param refresh_token body RefreshTokenRequest true "刷新令牌请求"
// @Success 200 {object} response.Response{data=model.JWTTokenPair} "刷新成功"
// @Failure 400 {object} response.Response "请求参数错误"
// @Failure 401 {object} response.Response "刷新令牌无效"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/refresh [post]
func (ctrl *JWTController) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// 尝试从Cookie获取刷新令牌
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil || refreshToken == "" {
			response.BadRequest(c, "缺少刷新令牌")
			return
		}
		req.RefreshToken = refreshToken
	}

	if req.RefreshToken == "" {
		response.BadRequest(c, "刷新令牌不能为空")
		return
	}

	// 获取客户端信息
	ipAddress, userAgent := middleware.GetClientInfo(c)

	// 刷新令牌
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	newTokenPair, err := ctrl.jwtService.RefreshToken(ctx, req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		response.Unauthorized(c, "刷新令牌失败: "+err.Error())
		return
	}

	// 更新Cookie中的刷新令牌
	c.SetCookie(
		"refresh_token",
		newTokenPair.RefreshToken,
		int(time.Until(newTokenPair.ExpiresAt).Seconds()),
		"/",
		"",
		false, // secure
		true,  // httpOnly
	)

	response.Success(c, "令牌刷新成功", newTokenPair)
}

// Logout 用户登出
// @Summary 用户登出
// @Description 撤销当前用户的访问令牌
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response "登出成功"
// @Failure 401 {object} response.Response "未认证"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/logout [post]
func (ctrl *JWTController) Logout(c *gin.Context) {
	// 获取当前用户信息
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.Unauthorized(c, "未认证")
		return
	}

	// 获取当前令牌
	token := extractTokenFromContext(c)
	if token == "" {
		response.BadRequest(c, "无法获取当前令牌")
		return
	}

	// 撤销访问令牌
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := ctrl.jwtService.RevokeToken(ctx, token, userID, "access"); err != nil {
		response.InternalServerError(c, "撤销令牌失败: "+err.Error())
		return
	}

	// 清除Cookie中的刷新令牌
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	response.Success(c, "登出成功", nil)
}

// LogoutAll 登出所有设备
// @Summary 登出所有设备
// @Description 撤销当前用户的所有令牌
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response "登出成功"
// @Failure 401 {object} response.Response "未认证"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/logout-all [post]
func (ctrl *JWTController) LogoutAll(c *gin.Context) {
	// 获取当前用户信息
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.Unauthorized(c, "未认证")
		return
	}

	// 撤销用户所有令牌
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if err := ctrl.jwtService.RevokeAllUserTokens(ctx, userID); err != nil {
		response.InternalServerError(c, "撤销所有令牌失败: "+err.Error())
		return
	}

	// 清除Cookie中的刷新令牌
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	response.Success(c, "已登出所有设备", nil)
}

// ValidateToken 验证令牌
// @Summary 验证令牌
// @Description 验证JWT令牌的有效性
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response{data=TokenValidationResponse} "令牌有效"
// @Failure 401 {object} response.Response "令牌无效"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/validate [get]
func (ctrl *JWTController) ValidateToken(c *gin.Context) {
	// 获取当前用户信息
	userID, exists := middleware.GetUserID(c)
	if !exists {
		response.Unauthorized(c, "未认证")
		return
	}

	tokenID, _ := middleware.GetTokenID(c)
	tokenType, _ := middleware.GetTokenType(c)

	// 构造响应
	resp := TokenValidationResponse{
		Valid:       true,
		UserID:      userID,
		TokenID:     tokenID,
		TokenType:   tokenType,
		ValidatedAt: time.Now(),
	}

	response.Success(c, "令牌有效", resp)
}

// GetStats 获取JWT统计信息
// @Summary 获取JWT统计信息
// @Description 获取JWT使用统计信息（需要管理员权限）
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response{data=service.JWTStats} "获取成功"
// @Failure 401 {object} response.Response "未认证"
// @Failure 403 {object} response.Response "权限不足"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/stats [get]
func (ctrl *JWTController) GetStats(c *gin.Context) {
	// TODO: 检查管理员权限
	// if !ctrl.hasAdminPermission(c) {
	//     response.Forbidden(c, "权限不足")
	//     return
	// }

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	stats, err := ctrl.jwtService.GetStats(ctx)
	if err != nil {
		response.InternalServerError(c, "获取统计信息失败: "+err.Error())
		return
	}

	response.Success(c, "获取统计信息成功", stats)
}

// CleanupExpiredTokens 清理过期令牌
// @Summary 清理过期令牌
// @Description 手动触发清理过期令牌（需要管理员权限）
// @Tags 认证
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.Response "清理成功"
// @Failure 401 {object} response.Response "未认证"
// @Failure 403 {object} response.Response "权限不足"
// @Failure 500 {object} response.Response "服务器内部错误"
// @Router /api/auth/cleanup [post]
func (ctrl *JWTController) CleanupExpiredTokens(c *gin.Context) {
	// TODO: 检查管理员权限
	// if !ctrl.hasAdminPermission(c) {
	//     response.Forbidden(c, "权限不足")
	//     return
	// }

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	if err := ctrl.jwtService.CleanupExpiredTokens(ctx); err != nil {
		response.InternalServerError(c, "清理过期令牌失败: "+err.Error())
		return
	}

	response.Success(c, "清理过期令牌成功", nil)
}

// extractTokenFromContext 从上下文中提取原始令牌
func extractTokenFromContext(c *gin.Context) string {
	// 从Authorization头获取
	auth := c.GetHeader("Authorization")
	if auth != "" {
		if len(auth) > 7 && auth[:7] == "Bearer " {
			return auth[7:]
		}
		return auth
	}

	// 从查询参数获取
	token := c.Query("token")
	if token != "" {
		return token
	}

	// 从Cookie获取
	cookie, err := c.Cookie("access_token")
	if err == nil && cookie != "" {
		return cookie
	}

	return ""
}

// 请求和响应结构体

// RefreshTokenRequest 刷新令牌请求
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// TokenValidationResponse 令牌验证响应
type TokenValidationResponse struct {
	Valid       bool      `json:"valid"`
	UserID      uint      `json:"user_id"`
	TokenID     string    `json:"token_id"`
	TokenType   string    `json:"token_type"`
	ValidatedAt time.Time `json:"validated_at"`
}

// RegisterRoutes 注册路由
func (ctrl *JWTController) RegisterRoutes(router *gin.RouterGroup, jwtMiddleware *middleware.JWTMiddleware) {
	auth := router.Group("/auth")
	{
		// 公开接口
		auth.POST("/login", ctrl.Login)
		auth.POST("/refresh", ctrl.RefreshToken)

		// 需要认证的接口
		protected := auth.Group("")
		protected.Use(jwtMiddleware.AuthRequired())
		{
			protected.POST("/logout", ctrl.Logout)
			protected.POST("/logout-all", ctrl.LogoutAll)
			protected.GET("/validate", ctrl.ValidateToken)
		}

		// 管理员接口
		admin := auth.Group("/admin")
		admin.Use(jwtMiddleware.AuthRequired())
		// admin.Use(jwtMiddleware.RoleRequired("admin", "super_admin"))
		{
			admin.GET("/stats", ctrl.GetStats)
			admin.POST("/cleanup", ctrl.CleanupExpiredTokens)
		}
	}
}
