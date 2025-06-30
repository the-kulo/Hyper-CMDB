package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"h-cmdb/internal/service"
)

// LoadJWTConfig 从环境变量加载JWT配置
func LoadJWTConfig() (*service.JWTConfig, error) {
	config := &service.JWTConfig{
		// 默认值
		BlacklistCacheExpire: time.Hour * 24,
		TokenCacheExpire:     time.Hour * 2,
		MaxRetries:           3,
		RetryDelay:           time.Millisecond * 100,
	}

	// JWT密钥
	secretKey := os.Getenv("JWT_SECRET_KEY")
	if secretKey == "" {
		return nil, fmt.Errorf("JWT_SECRET_KEY环境变量未设置")
	}
	config.SecretKey = secretKey

	// 访问令牌过期时间
	accessExpireStr := os.Getenv("JWT_ACCESS_TOKEN_EXPIRE")
	if accessExpireStr == "" {
		accessExpireStr = "8h" // 默认8小时
	}
	accessExpire, err := time.ParseDuration(accessExpireStr)
	if err != nil {
		return nil, fmt.Errorf("解析JWT_ACCESS_TOKEN_EXPIRE失败: %w", err)
	}
	config.AccessTokenExpire = accessExpire

	// 刷新令牌过期时间
	refreshExpireStr := os.Getenv("JWT_REFRESH_TOKEN_EXPIRE")
	if refreshExpireStr == "" {
		refreshExpireStr = "24h" // 默认24小时
	}
	refreshExpire, err := time.ParseDuration(refreshExpireStr)
	if err != nil {
		return nil, fmt.Errorf("解析JWT_REFRESH_TOKEN_EXPIRE失败: %w", err)
	}
	config.RefreshTokenExpire = refreshExpire

	// 刷新阈值
	refreshThresholdStr := os.Getenv("JWT_REFRESH_THRESHOLD")
	if refreshThresholdStr == "" {
		refreshThresholdStr = "10m" // 默认10分钟
	}
	refreshThreshold, err := time.ParseDuration(refreshThresholdStr)
	if err != nil {
		return nil, fmt.Errorf("解析JWT_REFRESH_THRESHOLD失败: %w", err)
	}
	config.RefreshThreshold = refreshThreshold

	// 发行者
	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "hyper-cmdb" // 默认值
	}
	config.Issuer = issuer

	// 算法
	algorithm := os.Getenv("JWT_ALGORITHM")
	if algorithm == "" {
		algorithm = "HS256" // 默认值
	}
	config.Algorithm = algorithm

	// 黑名单缓存过期时间
	blacklistCacheExpireStr := os.Getenv("JWT_BLACKLIST_CACHE_EXPIRE")
	if blacklistCacheExpireStr != "" {
		blacklistCacheExpire, err := time.ParseDuration(blacklistCacheExpireStr)
		if err != nil {
			return nil, fmt.Errorf("解析JWT_BLACKLIST_CACHE_EXPIRE失败: %w", err)
		}
		config.BlacklistCacheExpire = blacklistCacheExpire
	}

	// 令牌缓存过期时间
	tokenCacheExpireStr := os.Getenv("JWT_TOKEN_CACHE_EXPIRE")
	if tokenCacheExpireStr != "" {
		tokenCacheExpire, err := time.ParseDuration(tokenCacheExpireStr)
		if err != nil {
			return nil, fmt.Errorf("解析JWT_TOKEN_CACHE_EXPIRE失败: %w", err)
		}
		config.TokenCacheExpire = tokenCacheExpire
	}

	// 最大重试次数
	maxRetriesStr := os.Getenv("JWT_MAX_RETRIES")
	if maxRetriesStr != "" {
		maxRetries, err := strconv.Atoi(maxRetriesStr)
		if err != nil {
			return nil, fmt.Errorf("解析JWT_MAX_RETRIES失败: %w", err)
		}
		config.MaxRetries = maxRetries
	}

	// 重试延迟
	retryDelayStr := os.Getenv("JWT_RETRY_DELAY")
	if retryDelayStr != "" {
		retryDelay, err := time.ParseDuration(retryDelayStr)
		if err != nil {
			return nil, fmt.Errorf("解析JWT_RETRY_DELAY失败: %w", err)
		}
		config.RetryDelay = retryDelay
	}

	return config, nil
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
}

// LoadDatabaseConfig 加载数据库配置
func LoadDatabaseConfig() (*DatabaseConfig, error) {
	config := &DatabaseConfig{}

	// MySQL配置
	config.Host = os.Getenv("MYSQL_DB_HOST")
	if config.Host == "" {
		return nil, fmt.Errorf("MYSQL_DB_HOST环境变量未设置")
	}

	portStr := os.Getenv("MYSQL_DB_PORT")
	if portStr == "" {
		config.Port = 3306 // 默认端口
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("解析MYSQL_DB_PORT失败: %w", err)
		}
		config.Port = port
	}

	config.User = os.Getenv("MYSQL_DB_USER")
	if config.User == "" {
		return nil, fmt.Errorf("MYSQL_DB_USER环境变量未设置")
	}

	config.Password = os.Getenv("MYSQL_DB_PASSWORD")
	if config.Password == "" {
		return nil, fmt.Errorf("MYSQL_DB_PASSWORD环境变量未设置")
	}

	config.DBName = os.Getenv("MySQL_DB_NAME")
	if config.DBName == "" {
		return nil, fmt.Errorf("MySQL_DB_NAME环境变量未设置")
	}

	return config, nil
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// LoadRedisConfig 加载Redis配置
func LoadRedisConfig() (*RedisConfig, error) {
	config := &RedisConfig{
		DB: 0, // 默认数据库
	}

	config.Host = os.Getenv("Redis_Host")
	if config.Host == "" {
		return nil, fmt.Errorf("Redis_Host环境变量未设置")
	}

	portStr := os.Getenv("Redis_Port")
	if portStr == "" {
		config.Port = 6379 // 默认端口
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("解析Redis_Port失败: %w", err)
		}
		config.Port = port
	}

	config.Password = os.Getenv("Redis_Password")
	// Redis密码可以为空

	// Redis数据库编号
	dbStr := os.Getenv("Redis_DB")
	if dbStr != "" {
		db, err := strconv.Atoi(dbStr)
		if err != nil {
			return nil, fmt.Errorf("解析Redis_DB失败: %w", err)
		}
		config.DB = db
	}

	return config, nil
}

// GetDSN 获取MySQL数据源名称
func (c *DatabaseConfig) GetDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		c.User, c.Password, c.Host, c.Port, c.DBName)
}

// GetRedisAddr 获取Redis地址
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}