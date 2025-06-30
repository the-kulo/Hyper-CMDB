package service

import (
	"context"
	"fmt"
	"time"

	"h-cmdb/internal/model"
)

// processLogs 异步处理JWT日志
func (j *jwtService) processLogs() {
	for {
		select {
		case logItem := <-j.logChannel:
			if err := j.saveLogToDB(logItem); err != nil {
				// 日志保存失败，可以考虑重试或记录到文件
				fmt.Printf("保存JWT日志失败: %v\n", err)
			}
		case <-j.ctx.Done():
			// 服务关闭，处理剩余的日志
			j.drainLogChannel()
			return
		}
	}
}

// processBlacklist 异步处理黑名单
func (j *jwtService) processBlacklist() {
	batch := make([]*model.BlacklistItem, 0, 100) // 批处理大小
	ticker := time.NewTicker(time.Second * 5)     // 每5秒处理一次批量
	defer ticker.Stop()

	for {
		select {
		case item := <-j.blackChannel:
			batch = append(batch, item)
			// 如果批次满了，立即处理
			if len(batch) >= 100 {
				j.processBatch(batch)
				batch = batch[:0] // 清空批次
			}
		case <-ticker.C:
			// 定时处理批次
			if len(batch) > 0 {
				j.processBatch(batch)
				batch = batch[:0] // 清空批次
			}
		case <-j.ctx.Done():
			// 服务关闭，处理剩余的黑名单项
			if len(batch) > 0 {
				j.processBatch(batch)
			}
			j.drainBlacklistChannel()
			return
		}
	}
}

// cleanupRoutine 定期清理过期数据
func (j *jwtService) cleanupRoutine() {
	ticker := time.NewTicker(time.Hour) // 每小时清理一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
			if err := j.CleanupExpiredTokens(ctx); err != nil {
				fmt.Printf("清理过期令牌失败: %v\n", err)
			}
			cancel()
		case <-j.ctx.Done():
			return
		}
	}
}

// saveLogToDB 保存日志到数据库
func (j *jwtService) saveLogToDB(logItem *model.JWTLogItem) error {
	log := &model.JWTLog{
		UserID:       logItem.UserID,
		Action:       logItem.Action,
		TokenType:    logItem.TokenType,
		IPAddress:    logItem.IPAddress,
		UserAgent:    logItem.UserAgent,
		Success:      logItem.Success,
		ErrorMessage: logItem.ErrorMessage,
		CreatedAt:    logItem.CreatedAt,
	}

	// 使用重试机制
	var err error
	for i := 0; i < j.config.MaxRetries; i++ {
		err = j.db.Create(log).Error
		if err == nil {
			return nil
		}
		// 等待后重试
		time.Sleep(j.config.RetryDelay)
	}

	return fmt.Errorf("保存日志失败，重试%d次后仍然失败: %w", j.config.MaxRetries, err)
}

// processBatch 批量处理黑名单项
func (j *jwtService) processBatch(batch []*model.BlacklistItem) {
	if len(batch) == 0 {
		return
	}

	// 转换为数据库模型
	blacklists := make([]*model.JWTBlacklist, len(batch))
	for i, item := range batch {
		blacklists[i] = &model.JWTBlacklist{
			TokenID:   item.TokenID,
			UserID:    item.UserID,
			TokenType: item.TokenType,
			ExpiredAt: item.ExpiredAt,
			CreatedAt: item.CreatedAt,
			UpdatedAt: time.Now(),
		}
	}

	// 批量插入数据库
	var err error
	for i := 0; i < j.config.MaxRetries; i++ {
		err = j.db.CreateInBatches(blacklists, 50).Error
		if err == nil {
			return
		}
		// 等待后重试
		time.Sleep(j.config.RetryDelay)
	}

	fmt.Printf("批量保存黑名单失败，重试%d次后仍然失败: %v\n", j.config.MaxRetries, err)
}

// drainLogChannel 排空日志通道
func (j *jwtService) drainLogChannel() {
	for {
		select {
		case logItem := <-j.logChannel:
			if err := j.saveLogToDB(logItem); err != nil {
				fmt.Printf("关闭时保存JWT日志失败: %v\n", err)
			}
		default:
			return
		}
	}
}

// drainBlacklistChannel 排空黑名单通道
func (j *jwtService) drainBlacklistChannel() {
	batch := make([]*model.BlacklistItem, 0, 100)
	for {
		select {
		case item := <-j.blackChannel:
			batch = append(batch, item)
			if len(batch) >= 100 {
				j.processBatch(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 {
				j.processBatch(batch)
			}
			return
		}
	}
}

// logAsync 异步记录日志
func (j *jwtService) logAsync(logItem *model.JWTLogItem) {
	select {
	case j.logChannel <- logItem:
		// 成功发送到异步处理通道
	default:
		// 通道满了，同步保存
		if err := j.saveLogToDB(logItem); err != nil {
			fmt.Printf("同步保存JWT日志失败: %v\n", err)
		}
	}
}

// Close 关闭JWT服务
func (j *jwtService) Close() error {
	j.cancel() // 取消上下文，通知所有协程退出

	// 等待一段时间让协程处理完剩余数据
	time.Sleep(time.Second * 2)

	// 关闭通道
	close(j.logChannel)
	close(j.blackChannel)

	return nil
}

// GetStats 获取JWT统计信息
func (j *jwtService) GetStats(ctx context.Context) (*JWTStats, error) {
	stats := &JWTStats{}

	// 获取黑名单统计
	var blacklistStats model.BlacklistStats
	if err := j.db.WithContext(ctx).Model(&model.JWTBlacklist{}).Select(
		"COUNT(*) as total, "+
			"SUM(CASE WHEN expired_at > NOW() THEN 1 ELSE 0 END) as active, "+
			"SUM(CASE WHEN expired_at <= NOW() THEN 1 ELSE 0 END) as expired, "+
			"SUM(CASE WHEN token_type = 'access' THEN 1 ELSE 0 END) as access_tokens, "+
			"SUM(CASE WHEN token_type = 'refresh' THEN 1 ELSE 0 END) as refresh_tokens",
	).Scan(&blacklistStats).Error; err != nil {
		return nil, fmt.Errorf("获取黑名单统计失败: %w", err)
	}
	stats.BlacklistStats = blacklistStats

	// 获取日志统计
	var logStats model.LogStats
	if err := j.db.WithContext(ctx).Model(&model.JWTLog{}).Select(
		"COUNT(*) as total, "+
			"SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as success, "+
			"SUM(CASE WHEN success = false THEN 1 ELSE 0 END) as failed, "+
			"SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today",
	).Scan(&logStats).Error; err != nil {
		return nil, fmt.Errorf("获取日志统计失败: %w", err)
	}

	// 获取按操作类型统计
	var actionStats []struct {
		Action string `json:"action"`
		Count  int64  `json:"count"`
	}
	if err := j.db.WithContext(ctx).Model(&model.JWTLog{}).Select(
		"action, COUNT(*) as count",
	).Group("action").Scan(&actionStats).Error; err != nil {
		return nil, fmt.Errorf("获取操作统计失败: %w", err)
	}

	logStats.ByAction = make(map[string]int64)
	for _, stat := range actionStats {
		logStats.ByAction[stat.Action] = stat.Count
	}
	stats.LogStats = logStats

	// 获取用户活动统计（最活跃的10个用户）
	var userActivities []model.UserActivity
	if err := j.db.WithContext(ctx).Model(&model.JWTLog{}).Select(
		"user_id, COUNT(*) as activity_count, MAX(created_at) as last_activity",
	).Where("user_id IS NOT NULL").Group("user_id").Order("activity_count DESC").Limit(10).Scan(&userActivities).Error; err != nil {
		return nil, fmt.Errorf("获取用户活动统计失败: %w", err)
	}
	stats.UserActivities = userActivities

	return stats, nil
}