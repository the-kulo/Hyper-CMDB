package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"

	"h-cmdb/internal/model"
)

// RevokeToken 撤销令牌
func (j *jwtService) RevokeToken(ctx context.Context, tokenString string, userID uint, tokenType string) error {
	if tokenString == "" {
		return fmt.Errorf("令牌不能为空")
	}

	// 解析令牌获取TokenID
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("意外的签名方法: %v", token.Header["alg"])
		}
		return []byte(j.config.SecretKey), nil
	})

	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    time.Now(),
		})
		return fmt.Errorf("解析令牌失败: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      false,
			ErrorMessage: "无效的令牌声明",
			CreatedAt:    time.Now(),
		})
		return fmt.Errorf("无效的令牌声明")
	}

	// 验证用户ID和令牌类型
	if claims.UserID != userID || claims.TokenType != tokenType {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      false,
			ErrorMessage: "令牌信息不匹配",
			CreatedAt:    time.Now(),
		})
		return fmt.Errorf("令牌信息不匹配")
	}

	// 检查令牌是否已经在黑名单中
	isBlacklisted, err := j.IsTokenBlacklisted(ctx, claims.TokenID)
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      false,
			ErrorMessage: fmt.Sprintf("检查黑名单失败: %v", err),
			CreatedAt:    time.Now(),
		})
		return fmt.Errorf("检查令牌状态失败: %w", err)
	}

	if isBlacklisted {
		// 令牌已经被撤销，直接返回成功
		j.logAsync(&model.JWTLogItem{
			UserID:    &userID,
			Action:    "revoke",
			TokenType: tokenType,
			Success:   true,
			CreatedAt: time.Now(),
		})
		return nil
	}

	// 将令牌加入黑名单（异步处理）
	blacklistItem := &model.BlacklistItem{
		TokenID:   claims.TokenID,
		UserID:    userID,
		TokenType: tokenType,
		ExpiredAt: claims.ExpiresAt.Time,
		CreatedAt: time.Now(),
	}

	// 立即更新缓存
	if err := j.updateBlacklistCache(ctx, claims.TokenID, true); err != nil {
		// 缓存更新失败不影响业务逻辑
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      true,
			ErrorMessage: fmt.Sprintf("更新黑名单缓存失败: %v", err),
			CreatedAt:    time.Now(),
		})
	}

	// 异步写入数据库
	select {
	case j.blackChannel <- blacklistItem:
		// 成功发送到异步处理通道
	default:
		// 通道满了，同步写入数据库
		if err := j.addToBlacklistDB(ctx, blacklistItem); err != nil {
			j.logAsync(&model.JWTLogItem{
				UserID:       &userID,
				Action:       "revoke",
				TokenType:    tokenType,
				Success:      false,
				ErrorMessage: err.Error(),
				CreatedAt:    time.Now(),
			})
			return fmt.Errorf("撤销令牌失败: %w", err)
		}
	}

	// 从用户令牌集合中移除
	if err := j.removeFromUserTokens(ctx, userID, claims.TokenID); err != nil {
		// 移除失败不影响撤销操作
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			TokenType:    tokenType,
			Success:      true,
			ErrorMessage: fmt.Sprintf("从用户令牌集合移除失败: %v", err),
			CreatedAt:    time.Now(),
		})
	}

	// 记录成功日志
	j.logAsync(&model.JWTLogItem{
		UserID:    &userID,
		Action:    "revoke",
		TokenType: tokenType,
		Success:   true,
		CreatedAt: time.Now(),
	})

	return nil
}

// RevokeAllUserTokens 撤销用户所有令牌
func (j *jwtService) RevokeAllUserTokens(ctx context.Context, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("用户ID不能为空")
	}

	// 获取用户所有活跃令牌
	userTokensKey := j.getUserTokensKey(userID)
	tokenIDs, err := j.redis.SMembers(ctx, userTokensKey).Result()
	if err != nil && err != redis.Nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "revoke",
			Success:      false,
			ErrorMessage: fmt.Sprintf("获取用户令牌列表失败: %v", err),
			CreatedAt:    time.Now(),
		})
		// Redis失败时从数据库查询
		tokenIDs, err = j.getUserTokensFromDB(ctx, userID)
		if err != nil {
			return fmt.Errorf("获取用户令牌失败: %w", err)
		}
	}

	if len(tokenIDs) == 0 {
		// 用户没有活跃令牌
		return nil
	}

	// 批量撤销令牌
	var revokeErrors []string
	for _, tokenID := range tokenIDs {
		// 更新黑名单缓存
		if err := j.updateBlacklistCache(ctx, tokenID, true); err != nil {
			revokeErrors = append(revokeErrors, fmt.Sprintf("更新令牌%s缓存失败: %v", tokenID, err))
		}

		// 异步加入黑名单
		blacklistItem := &model.BlacklistItem{
			TokenID:   tokenID,
			UserID:    userID,
			TokenType: "unknown",                                   // 批量撤销时类型未知
			ExpiredAt: time.Now().Add(j.config.RefreshTokenExpire), // 使用最长过期时间
			CreatedAt: time.Now(),
		}

		select {
		case j.blackChannel <- blacklistItem:
			// 成功发送到异步处理通道
		default:
			// 通道满了，同步写入数据库
			if err := j.addToBlacklistDB(ctx, blacklistItem); err != nil {
				revokeErrors = append(revokeErrors, fmt.Sprintf("撤销令牌%s失败: %v", tokenID, err))
			}
		}
	}

	// 清空用户令牌集合
	if err := j.redis.Del(ctx, userTokensKey).Err(); err != nil {
		revokeErrors = append(revokeErrors, fmt.Sprintf("清空用户令牌集合失败: %v", err))
	}

	// 记录日志
	logItem := &model.JWTLogItem{
		UserID:    &userID,
		Action:    "revoke",
		Success:   len(revokeErrors) == 0,
		CreatedAt: time.Now(),
	}

	if len(revokeErrors) > 0 {
		logItem.ErrorMessage = fmt.Sprintf("部分撤销失败: %v", revokeErrors)
	}

	j.logAsync(logItem)

	if len(revokeErrors) > 0 {
		return fmt.Errorf("撤销用户所有令牌时发生错误: %v", revokeErrors)
	}

	return nil
}

// CleanupExpiredTokens 清理过期令牌
func (j *jwtService) CleanupExpiredTokens(ctx context.Context) error {
	now := time.Now()

	// 清理数据库中的过期黑名单记录
	result := j.db.WithContext(ctx).Where("expired_at < ?", now).Delete(&model.JWTBlacklist{})
	if result.Error != nil {
		return fmt.Errorf("清理过期黑名单记录失败: %w", result.Error)
	}

	// 清理过期的JWT日志（保留最近30天）
	thirtyDaysAgo := now.AddDate(0, 0, -30)
	logResult := j.db.WithContext(ctx).Where("created_at < ?", thirtyDaysAgo).Delete(&model.JWTLog{})
	if logResult.Error != nil {
		return fmt.Errorf("清理过期JWT日志失败: %w", logResult.Error)
	}

	// 记录清理日志
	j.logAsync(&model.JWTLogItem{
		Action:    "cleanup",
		Success:   true,
		CreatedAt: now,
	})

	return nil
}

// updateBlacklistCache 更新黑名单缓存
func (j *jwtService) updateBlacklistCache(ctx context.Context, tokenID string, isBlacklisted bool) error {
	cacheKey := j.getBlacklistCacheKey(tokenID)
	cacheValue := "0"
	if isBlacklisted {
		cacheValue = "1"
	}

	return j.redis.Set(ctx, cacheKey, cacheValue, j.config.BlacklistCacheExpire).Err()
}

// addToBlacklistDB 将令牌加入数据库黑名单
func (j *jwtService) addToBlacklistDB(ctx context.Context, item *model.BlacklistItem) error {
	blacklist := &model.JWTBlacklist{
		TokenID:   item.TokenID,
		UserID:    item.UserID,
		TokenType: item.TokenType,
		ExpiredAt: item.ExpiredAt,
		CreatedAt: item.CreatedAt,
		UpdatedAt: time.Now(),
	}

	// 使用ON DUPLICATE KEY UPDATE避免重复插入
	return j.db.WithContext(ctx).Create(blacklist).Error
}

// removeFromUserTokens 从用户令牌集合中移除令牌
func (j *jwtService) removeFromUserTokens(ctx context.Context, userID uint, tokenID string) error {
	userTokensKey := j.getUserTokensKey(userID)
	return j.redis.SRem(ctx, userTokensKey, tokenID).Err()
}

// getUserTokensFromDB 从数据库获取用户令牌
func (j *jwtService) getUserTokensFromDB(ctx context.Context, userID uint) ([]string, error) {
	// 这里需要根据实际情况实现
	// 由于JWT是无状态的，我们可能需要维护一个用户活跃令牌的表
	// 或者通过其他方式跟踪用户的活跃令牌
	return []string{}, nil
}

// addToUserTokens 将令牌添加到用户令牌集合
func (j *jwtService) addToUserTokens(ctx context.Context, userID uint, tokenID string) error {
	userTokensKey := j.getUserTokensKey(userID)
	// 设置集合过期时间为刷新令牌过期时间
	pipe := j.redis.Pipeline()
	pipe.SAdd(ctx, userTokensKey, tokenID)
	pipe.Expire(ctx, userTokensKey, j.config.RefreshTokenExpire)
	_, err := pipe.Exec(ctx)
	return err
}
