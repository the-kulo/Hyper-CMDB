package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"h-cmdb/internal/model"
)

// TokenInfo 令牌信息结构
type TokenInfo struct {
	UserID    uint      `json:"user_id"`
	TokenType string    `json:"token_type"`
	ExpiredAt time.Time `json:"expired_at"`
}

// ValidateAccessToken 验证访问令牌
func (j *jwtService) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.Token, *JWTClaims, error) {
	if tokenString == "" {
		return nil, nil, errors.New("令牌不能为空")
	}

	// 解析令牌
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return []byte(j.config.SecretKey), nil
	})

	if err != nil {
		j.logAsync(&model.JWTLogItem{
			Action:       "validate",
			TokenType:    "access",
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})
		return nil, nil, fmt.Errorf("解析令牌失败: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		j.logAsync(&model.JWTLogItem{
			Action:       "validate",
			TokenType:    "access",
			Success:      false,
			ErrorMessage: "无效的令牌声明",
			CreatedAt:    time.Now(),
		})
		return nil, nil, errors.New("无效的令牌")
	}

	// 检查令牌类型
	if claims.TokenType != "access" {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "validate",
			TokenType:    claims.TokenType,
			Success:      false,
			ErrorMessage: "令牌类型不匹配",
			CreatedAt:    time.Now(),
		})
		return nil, nil, errors.New("令牌类型不匹配")
	}

	// 检查令牌是否在黑名单中（使用缓存穿透防护）
	isBlacklisted, err := j.IsTokenBlacklisted(ctx, claims.TokenID)
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "validate",
			TokenType:    "access",
			Success:      false,
			ErrorMessage: fmt.Sprintf("检查黑名单失败: %v", err),
			CreatedAt:    time.Now(),
		})
		return nil, nil, fmt.Errorf("检查令牌状态失败: %w", err)
	}

	if isBlacklisted {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "validate",
			TokenType:    "access",
			Success:      false,
			ErrorMessage: "令牌已被撤销",
			CreatedAt:    time.Now(),
		})
		return nil, nil, errors.New("令牌已被撤销")
	}

	// 记录成功验证日志
	j.logAsync(&model.JWTLogItem{
		UserID:    &claims.UserID,
		Action:    "validate",
		TokenType: "access",
		Success:   true,
		CreatedAt: time.Now(),
	})

	return token, claims, nil
}

// IsTokenBlacklisted 检查令牌是否在黑名单中（带缓存穿透防护）
func (j *jwtService) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, errors.New("令牌ID不能为空")
	}

	// 1. 先检查Redis缓存
	cacheKey := j.getBlacklistCacheKey(tokenID)
	cachedResult, err := j.redis.Get(ctx, cacheKey).Result()
	if err == nil {
		// 缓存命中
		return cachedResult == "1", nil
	}

	if err != redis.Nil {
		// Redis错误，记录日志但继续查询数据库
		j.logAsync(&model.JWTLogItem{
			Action:       "validate",
			Success:      false,
			ErrorMessage: fmt.Sprintf("Redis查询失败: %v", err),
			CreatedAt:    time.Now(),
		})
	}

	// 2. 缓存未命中，查询数据库
	var count int64
	err = j.db.WithContext(ctx).Model(&model.JWTBlacklist{}).
		Where("token_id = ? AND expired_at > ?", tokenID, time.Now()).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("查询黑名单失败: %w", err)
	}

	isBlacklisted := count > 0

	// 3. 将结果缓存到Redis（防止缓存穿透）
	cacheValue := "0"
	if isBlacklisted {
		cacheValue = "1"
	}

	// 设置缓存，即使是负结果也要缓存（防止缓存穿透）
	expire := j.config.BlacklistCacheExpire
	if !isBlacklisted {
		// 负结果缓存时间较短
		expire = time.Minute * 5
	}

	if err := j.redis.Set(ctx, cacheKey, cacheValue, expire).Err(); err != nil {
		// 缓存设置失败不影响业务逻辑
		j.logAsync(&model.JWTLogItem{
			Action:       "validate",
			Success:      true,
			ErrorMessage: fmt.Sprintf("设置黑名单缓存失败: %v", err),
			CreatedAt:    time.Now(),
		})
	}

	return isBlacklisted, nil
}

// RefreshToken 刷新令牌
func (j *jwtService) RefreshToken(ctx context.Context, refreshToken, userAgent, ipAddress string) (*model.JWTTokenPair, error) {
	if refreshToken == "" {
		return nil, errors.New("刷新令牌不能为空")
	}

	// 解析刷新令牌
	token, err := jwt.ParseWithClaims(refreshToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return []byte(j.config.SecretKey), nil
	})

	if err != nil {
		j.logAsync(&model.JWTLogItem{
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})
		return nil, fmt.Errorf("解析刷新令牌失败: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		j.logAsync(&model.JWTLogItem{
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: "无效的刷新令牌",
			CreatedAt:    time.Now(),
		})
		return nil, errors.New("无效的刷新令牌")
	}

	// 检查令牌类型
	if claims.TokenType != "refresh" {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    claims.TokenType,
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: "令牌类型不匹配",
			CreatedAt:    time.Now(),
		})
		return nil, errors.New("令牌类型不匹配")
	}

	// 检查刷新令牌是否在黑名单中
	isBlacklisted, err := j.IsTokenBlacklisted(ctx, claims.TokenID)
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: fmt.Sprintf("检查黑名单失败: %v", err),
			CreatedAt:    time.Now(),
		})
		return nil, fmt.Errorf("检查令牌状态失败: %w", err)
	}

	if isBlacklisted {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: "刷新令牌已被撤销",
			CreatedAt:    time.Now(),
		})
		return nil, errors.New("刷新令牌已被撤销")
	}

	// 检查是否需要刷新（距离过期时间小于阈值）
	if time.Until(claims.ExpiresAt.Time) > j.config.RefreshThreshold {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: "刷新令牌尚未到达刷新阈值",
			CreatedAt:    time.Now(),
		})
		return nil, errors.New("刷新令牌尚未到达刷新阈值")
	}

	// 将旧的刷新令牌加入黑名单
	if err := j.RevokeToken(ctx, refreshToken, claims.UserID, "refresh"); err != nil {
		// 撤销失败不影响新令牌生成，但要记录日志
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      true,
			ErrorMessage: fmt.Sprintf("撤销旧刷新令牌失败: %v", err),
			CreatedAt:    time.Now(),
		})
	}

	// 生成新的令牌对
	newTokenPair, err := j.GenerateTokenPair(ctx, claims.UserID, userAgent, ipAddress)
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &claims.UserID,
			Action:       "refresh",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})
		return nil, fmt.Errorf("生成新令牌对失败: %w", err)
	}

	// 记录成功刷新日志
	j.logAsync(&model.JWTLogItem{
		UserID:    &claims.UserID,
		Action:    "refresh",
		TokenType: "refresh",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		CreatedAt: time.Now(),
	})

	return newTokenPair, nil
}

// cacheTokenInfo 缓存令牌信息
func (j *jwtService) cacheTokenInfo(ctx context.Context, tokenID string, userID uint, tokenType string, expiredAt time.Time) error {
	tokenInfo := TokenInfo{
		UserID:    userID,
		TokenType: tokenType,
		ExpiredAt: expiredAt,
	}

	data, err := json.Marshal(tokenInfo)
	if err != nil {
		return fmt.Errorf("序列化令牌信息失败: %w", err)
	}

	cacheKey := j.getTokenCacheKey(tokenID)
	expire := time.Until(expiredAt)
	if expire > j.config.TokenCacheExpire {
		expire = j.config.TokenCacheExpire
	}

	return j.redis.Set(ctx, cacheKey, data, expire).Err()
}

// getBlacklistCacheKey 获取黑名单缓存键
func (j *jwtService) getBlacklistCacheKey(tokenID string) string {
	return fmt.Sprintf("jwt:blacklist:%s", tokenID)
}

// getTokenCacheKey 获取令牌缓存键
func (j *jwtService) getTokenCacheKey(tokenID string) string {
	return fmt.Sprintf("jwt:token:%s", tokenID)
}

// getUserTokensKey 获取用户令牌集合键
func (j *jwtService) getUserTokensKey(userID uint) string {
	return fmt.Sprintf("jwt:user:%d:tokens", userID)
}
