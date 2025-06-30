package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"h-cmdb/internal/response"
	"h-cmdb/internal/service"
)

// JWTMiddleware JWT中间件
type JWTMiddleware struct {
	jwtService service.JWTService
}

// NewJWTMiddleware 创建JWT中间件
func NewJWTMiddleware(jwtService service.JWTService) *JWTMiddleware {
	return &JWTMiddleware{
		jwtService: jwtService,
	}
}

// AuthRequired 需要认证的中间件
func (m *JWTMiddleware) AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取令牌
		token := m.extractToken(c)
		if token == "" {
			response.Unauthorized(c, "缺少认证令牌")
			c.Abort()
			return
		}

		// 验证令牌
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		_, claims, err := m.jwtService.ValidateAccessToken(ctx, token)
		if err != nil {
			response.Unauthorized(c, "无效的认证令牌: "+err.Error())
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", claims.UserID)
		c.Set("token_id", claims.TokenID)
		c.Set("token_type", claims.TokenType)

		// 继续处理请求
		c.Next()
	}
}

// OptionalAuth 可选认证中间件（不强制要求认证）
func (m *JWTMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从请求头获取令牌
		token := m.extractToken(c)
		if token == "" {
			// 没有令牌，继续处理请求
			c.Next()
			return
		}

		// 验证令牌
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		_, claims, err := m.jwtService.ValidateAccessToken(ctx, token)
		if err != nil {
			// 令牌无效，但不阻止请求继续
			c.Next()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", claims.UserID)
		c.Set("token_id", claims.TokenID)
		c.Set("token_type", claims.TokenType)

		// 继续处理请求
		c.Next()
	}
}

// RoleRequired 需要特定角色的中间件
func (m *JWTMiddleware) RoleRequired(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 首先确保用户已认证
		userID, exists := c.Get("user_id")
		if !exists {
			response.Unauthorized(c, "需要认证")
			c.Abort()
			return
		}

		// TODO: 这里需要根据userID查询用户角色
		// 由于这需要访问用户服务，这里先简化处理
		// 在实际项目中，你可能需要注入用户服务或者在JWT中包含角色信息

		// 示例：假设我们有一个用户服务来检查角色
		// userRoles, err := m.userService.GetUserRoles(userID.(uint))
		// if err != nil {
		//     response.InternalServerError(c, "获取用户角色失败")
		//     c.Abort()
		//     return
		// }

		// hasRequiredRole := false
		// for _, userRole := range userRoles {
		//     for _, requiredRole := range requiredRoles {
		//         if userRole == requiredRole {
		//             hasRequiredRole = true
		//             break
		//         }
		//     }
		//     if hasRequiredRole {
		//         break
		//     }
		// }

		// if !hasRequiredRole {
		//     response.Forbidden(c, "权限不足")
		//     c.Abort()
		//     return
		// }

		// 临时处理：直接通过
		_ = userID
		_ = requiredRoles

		// 继续处理请求
		c.Next()
	}
}

// RateLimitByUser 按用户限流中间件
func (m *JWTMiddleware) RateLimitByUser(maxRequests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			// 未认证用户，可以使用IP限流
			c.Next()
			return
		}

		// TODO: 实现基于Redis的用户限流
		// 这里需要使用Redis来跟踪用户的请求频率
		// key := fmt.Sprintf("rate_limit:user:%d", userID.(uint))
		// count, err := m.redis.Incr(ctx, key).Result()
		// if err != nil {
		//     // Redis错误，允许请求通过
		//     c.Next()
		//     return
		// }
		//
		// if count == 1 {
		//     // 第一次请求，设置过期时间
		//     m.redis.Expire(ctx, key, window)
		// }
		//
		// if count > int64(maxRequests) {
		//     response.TooManyRequests(c, "请求过于频繁")
		//     c.Abort()
		//     return
		// }

		// 临时处理：直接通过
		_ = userID
		_ = maxRequests
		_ = window

		c.Next()
	}
}

// LogRequest 请求日志中间件
func (m *JWTMiddleware) LogRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// 处理请求
		c.Next()

		// 记录请求日志
		duration := time.Since(start)
		userID, _ := c.Get("user_id")
		tokenID, _ := c.Get("token_id")

		// TODO: 这里可以记录详细的请求日志
		// 包括用户ID、令牌ID、请求路径、方法、状态码、耗时等
		_ = duration
		_ = userID
		_ = tokenID
	}
}

// extractToken 从请求中提取令牌
func (m *JWTMiddleware) extractToken(c *gin.Context) string {
	// 1. 从Authorization头获取
	auth := c.GetHeader("Authorization")
	if auth != "" {
		// 支持 "Bearer <token>" 格式
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
		// 直接返回令牌
		return auth
	}

	// 2. 从查询参数获取
	token := c.Query("token")
	if token != "" {
		return token
	}

	// 3. 从Cookie获取
	cookie, err := c.Cookie("access_token")
	if err == nil && cookie != "" {
		return cookie
	}

	return ""
}

// GetUserID 从上下文获取用户ID
func GetUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	id, ok := userID.(uint)
	return id, ok
}

// GetTokenID 从上下文获取令牌ID
func GetTokenID(c *gin.Context) (string, bool) {
	tokenID, exists := c.Get("token_id")
	if !exists {
		return "", false
	}
	id, ok := tokenID.(string)
	return id, ok
}

// GetTokenType 从上下文获取令牌类型
func GetTokenType(c *gin.Context) (string, bool) {
	tokenType, exists := c.Get("token_type")
	if !exists {
		return "", false
	}
	typ, ok := tokenType.(string)
	return typ, ok
}

// RequireAuth 检查是否已认证
func RequireAuth(c *gin.Context) bool {
	_, exists := c.Get("user_id")
	return exists
}

// GetClientInfo 获取客户端信息
func GetClientInfo(c *gin.Context) (ip, userAgent string) {
	// 获取真实IP地址
	ip = c.ClientIP()

	// 尝试从X-Forwarded-For头获取
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For可能包含多个IP，取第一个
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			ip = strings.TrimSpace(ips[0])
		}
	}

	// 尝试从X-Real-IP头获取
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		ip = realIP
	}

	// 获取User-Agent
	userAgent = c.GetHeader("User-Agent")

	return ip, userAgent
}
