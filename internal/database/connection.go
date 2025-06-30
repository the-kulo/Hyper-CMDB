package database

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"h-cmdb/internal/config"
	"h-cmdb/internal/model"
)

// DatabaseManager 数据库管理器
type DatabaseManager struct {
	DB    *gorm.DB
	Redis *redis.Client
}

// NewDatabaseManager 创建数据库管理器
func NewDatabaseManager() (*DatabaseManager, error) {
	// 加载数据库配置
	dbConfig, err := config.LoadDatabaseConfig()
	if err != nil {
		return nil, fmt.Errorf("加载数据库配置失败: %w", err)
	}

	// 加载Redis配置
	redisConfig, err := config.LoadRedisConfig()
	if err != nil {
		return nil, fmt.Errorf("加载Redis配置失败: %w", err)
	}

	// 初始化MySQL连接
	db, err := initMySQL(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("初始化MySQL连接失败: %w", err)
	}

	// 初始化Redis连接
	redisClient, err := initRedis(redisConfig)
	if err != nil {
		return nil, fmt.Errorf("初始化Redis连接失败: %w", err)
	}

	return &DatabaseManager{
		DB:    db,
		Redis: redisClient,
	}, nil
}

// initMySQL 初始化MySQL连接
func initMySQL(config *config.DatabaseConfig) (*gorm.DB, error) {
	dsn := config.GetDSN()

	// 配置GORM
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		// 禁用外键约束检查（可选）
		DisableForeignKeyConstraintWhenMigrating: true,
	}

	// 连接数据库
	db, err := gorm.Open(mysql.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("连接MySQL失败: %w", err)
	}

	// 获取底层sql.DB对象进行连接池配置
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("获取SQL DB失败: %w", err)
	}

	// 设置连接池参数
	sqlDB.SetMaxIdleConns(10)                  // 最大空闲连接数
	sqlDB.SetMaxOpenConns(100)                 // 最大打开连接数
	sqlDB.SetConnMaxLifetime(time.Hour)        // 连接最大生存时间
	sqlDB.SetConnMaxIdleTime(time.Minute * 30) // 连接最大空闲时间

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("MySQL连接测试失败: %w", err)
	}

	return db, nil
}

// initRedis 初始化Redis连接
func initRedis(config *config.RedisConfig) (*redis.Client, error) {
	// 创建Redis客户端
	rdb := redis.NewClient(&redis.Options{
		Addr:            config.GetRedisAddr(),
		Password:        config.Password,
		DB:              config.DB,
		PoolSize:        10,               // 连接池大小
		MinIdleConns:    5,                // 最小空闲连接数
		MaxIdleConns:    10,               // 最大空闲连接数
		ConnMaxIdleTime: time.Minute * 30, // 连接最大空闲时间
		DialTimeout:     time.Second * 5,  // 连接超时
		ReadTimeout:     time.Second * 3,  // 读取超时
		WriteTimeout:    time.Second * 3,  // 写入超时
	})

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis连接测试失败: %w", err)
	}

	return rdb, nil
}

// AutoMigrate 自动迁移数据库表结构
func (dm *DatabaseManager) AutoMigrate() error {
	// 迁移所有模型
	err := dm.DB.AutoMigrate(
		&model.User{},
		&model.Role{},
		&model.JWTBlacklist{},
		&model.JWTLog{},
	)
	if err != nil {
		return fmt.Errorf("数据库迁移失败: %w", err)
	}

	// 创建索引
	if err := dm.createIndexes(); err != nil {
		return fmt.Errorf("创建索引失败: %w", err)
	}

	return nil
}

// createIndexes 创建数据库索引
func (dm *DatabaseManager) createIndexes() error {
	// 定义需要创建的索引
	indexes := []struct {
		table string
		name  string
		sql   string
	}{
		// JWT黑名单表索引（注意：expired_at索引已在GORM模型中自动创建）
		{"jwt_blacklist", "idx_jwt_blacklist_token_type", "CREATE INDEX idx_jwt_blacklist_token_type ON jwt_blacklist(token_type)"},
		// JWT日志表索引（注意：user_id, action, created_at索引已在GORM模型中自动创建）
		{"jwt_logs", "idx_jwt_logs_success", "CREATE INDEX idx_jwt_logs_success ON jwt_logs(success)"},
	}

	// 遍历创建索引
	for _, idx := range indexes {
		if err := dm.createIndexIfNotExists(idx.table, idx.name, idx.sql); err != nil {
			return fmt.Errorf("创建%s.%s索引失败: %w", idx.table, idx.name, err)
		}
	}

	return nil
}

// createIndexIfNotExists 检查索引是否存在，如果不存在则创建
func (dm *DatabaseManager) createIndexIfNotExists(tableName, indexName, createSQL string) error {
	// 检查索引是否存在
	var count int64
	err := dm.DB.Raw(`
		SELECT COUNT(*) 
		FROM information_schema.statistics 
		WHERE table_schema = DATABASE() 
		  AND table_name = ? 
		  AND index_name = ?
	`, tableName, indexName).Scan(&count).Error

	if err != nil {
		return fmt.Errorf("检查索引存在性失败: %w", err)
	}

	// 如果索引不存在，则创建
	if count == 0 {
		if err := dm.DB.Exec(createSQL).Error; err != nil {
			return fmt.Errorf("创建索引失败: %w", err)
		}
	}

	return nil
}

// Close 关闭数据库连接
func (dm *DatabaseManager) Close() error {
	var errors []error

	// 关闭MySQL连接
	if dm.DB != nil {
		sqlDB, err := dm.DB.DB()
		if err == nil {
			if err := sqlDB.Close(); err != nil {
				errors = append(errors, fmt.Errorf("关闭MySQL连接失败: %w", err))
			}
		} else {
			errors = append(errors, fmt.Errorf("获取MySQL连接失败: %w", err))
		}
	}

	// 关闭Redis连接
	if dm.Redis != nil {
		if err := dm.Redis.Close(); err != nil {
			errors = append(errors, fmt.Errorf("关闭Redis连接失败: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("关闭数据库连接时发生错误: %v", errors)
	}

	return nil
}

// HealthCheck 健康检查
func (dm *DatabaseManager) HealthCheck(ctx context.Context) error {
	// 检查MySQL连接
	if dm.DB != nil {
		sqlDB, err := dm.DB.DB()
		if err != nil {
			return fmt.Errorf("获取MySQL连接失败: %w", err)
		}
		if err := sqlDB.PingContext(ctx); err != nil {
			return fmt.Errorf("MySQL健康检查失败: %w", err)
		}
	}

	// 检查Redis连接
	if dm.Redis != nil {
		if err := dm.Redis.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("Redis健康检查失败: %w", err)
		}
	}

	return nil
}

// GetStats 获取数据库统计信息
func (dm *DatabaseManager) GetStats() (*DatabaseStats, error) {
	stats := &DatabaseStats{}

	// MySQL统计
	if dm.DB != nil {
		sqlDB, err := dm.DB.DB()
		if err == nil {
			dbStats := sqlDB.Stats()
			stats.MySQL = &MySQLStats{
				MaxOpenConnections: dbStats.MaxOpenConnections,
				OpenConnections:    dbStats.OpenConnections,
				InUse:              dbStats.InUse,
				Idle:               dbStats.Idle,
			}
		}
	}

	// Redis统计
	if dm.Redis != nil {
		poolStats := dm.Redis.PoolStats()
		stats.Redis = &RedisStats{
			Hits:       poolStats.Hits,
			Misses:     poolStats.Misses,
			Timeouts:   poolStats.Timeouts,
			TotalConns: poolStats.TotalConns,
			IdleConns:  poolStats.IdleConns,
			StaleConns: poolStats.StaleConns,
		}
	}

	return stats, nil
}

// DatabaseStats 数据库统计信息
type DatabaseStats struct {
	MySQL *MySQLStats `json:"mysql,omitempty"`
	Redis *RedisStats `json:"redis,omitempty"`
}

// MySQLStats MySQL统计信息
type MySQLStats struct {
	MaxOpenConnections int `json:"max_open_connections"`
	OpenConnections    int `json:"open_connections"`
	InUse              int `json:"in_use"`
	Idle               int `json:"idle"`
}

// RedisStats Redis统计信息
type RedisStats struct {
	Hits       uint32 `json:"hits"`
	Misses     uint32 `json:"misses"`
	Timeouts   uint32 `json:"timeouts"`
	TotalConns uint32 `json:"total_conns"`
	IdleConns  uint32 `json:"idle_conns"`
	StaleConns uint32 `json:"stale_conns"`
}
