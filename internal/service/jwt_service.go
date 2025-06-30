package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"h-cmdb/internal/model"
)

// JWTService JWT服务接口
type JWTService interface {
	// 生成令牌对
	GenerateTokenPair(ctx context.Context, userID uint, userAgent, ipAddress string) (*model.JWTTokenPair, error)
	// 验证访问令牌
	ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.Token, *JWTClaims, error)
	// 刷新令牌
	RefreshToken(ctx context.Context, refreshToken, userAgent, ipAddress string) (*model.JWTTokenPair, error)
	// 撤销令牌
	RevokeToken(ctx context.Context, tokenString string, userID uint, tokenType string) error
	// 撤销用户所有令牌
	RevokeAllUserTokens(ctx context.Context, userID uint) error
	// 检查令牌是否在黑名单中
	IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error)
	// 清理过期令牌
	CleanupExpiredTokens(ctx context.Context) error
	// 获取JWT统计信息
	GetStats(ctx context.Context) (*JWTStats, error)
}

// JWTClaims JWT声明
type JWTClaims struct {
	UserID    uint   `json:"user_id"`
	TokenID   string `json:"token_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

// JWTConfig JWT配置
type JWTConfig struct {
	SecretKey            string
	AccessTokenExpire    time.Duration
	RefreshTokenExpire   time.Duration
	RefreshThreshold     time.Duration
	Issuer               string
	Algorithm            string
	BlacklistCacheExpire time.Duration // 黑名单缓存过期时间
	TokenCacheExpire     time.Duration // 令牌缓存过期时间
	MaxRetries           int           // 最大重试次数
	RetryDelay           time.Duration // 重试延迟
}

// JWTStats JWT统计信息
type JWTStats struct {
	BlacklistStats model.BlacklistStats   `json:"blacklist_stats"`
	LogStats       model.LogStats         `json:"log_stats"`
	UserActivities []model.UserActivity   `json:"user_activities"`
}

// jwtService JWT服务实现
type jwtService struct {
	config       *JWTConfig
	db           *gorm.DB
	redis        *redis.Client
	logChannel   chan *model.JWTLogItem    // 异步日志通道
	blackChannel chan *model.BlacklistItem // 异步黑名单通道
	mu           sync.RWMutex              // 读写锁
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewJWTService 创建JWT服务实例
func NewJWTService(config *JWTConfig, db *gorm.DB, redisClient *redis.Client) JWTService {
	ctx, cancel := context.WithCancel(context.Background())

	service := &jwtService{
		config:       config,
		db:           db,
		redis:        redisClient,
		logChannel:   make(chan *model.JWTLogItem, 1000),
		blackChannel: make(chan *model.BlacklistItem, 1000),
		ctx:          ctx,
		cancel:       cancel,
	}

	// 启动异步处理协程
	go service.processLogs()
	go service.processBlacklist()
	go service.cleanupRoutine()

	return service
}

// generateTokenID 生成唯一的令牌ID
func (j *jwtService) generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateTokenPair 生成令牌对
func (j *jwtService) GenerateTokenPair(ctx context.Context, userID uint, userAgent, ipAddress string) (*model.JWTTokenPair, error) {
	now := time.Now()
	accessTokenID, err := j.generateTokenID()
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "access",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    now,
		})
		return nil, fmt.Errorf("生成访问令牌ID失败: %w", err)
	}

	refreshTokenID, err := j.generateTokenID()
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    now,
		})
		return nil, fmt.Errorf("生成刷新令牌ID失败: %w", err)
	}

	// 生成访问令牌
	accessExpire := now.Add(j.config.AccessTokenExpire)
	accessClaims := &JWTClaims{
		UserID:    userID,
		TokenID:   accessTokenID,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpire),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(j.config.SecretKey))
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "access",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    now,
		})
		return nil, fmt.Errorf("签名访问令牌失败: %w", err)
	}

	// 生成刷新令牌
	refreshExpire := now.Add(j.config.RefreshTokenExpire)
	refreshClaims := &JWTClaims{
		UserID:    userID,
		TokenID:   refreshTokenID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.config.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(refreshExpire),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(j.config.SecretKey))
	if err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      false,
			ErrorMessage: err.Error(),
			CreatedAt:    now,
		})
		return nil, fmt.Errorf("签名刷新令牌失败: %w", err)
	}

	// 缓存令牌信息到Redis（用于快速验证）
	if err := j.cacheTokenInfo(ctx, accessTokenID, userID, "access", accessExpire); err != nil {
		// 缓存失败不影响令牌生成，只记录日志
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "access",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      true,
			ErrorMessage: fmt.Sprintf("缓存访问令牌失败: %v", err),
			CreatedAt:    now,
		})
	}

	if err := j.cacheTokenInfo(ctx, refreshTokenID, userID, "refresh", refreshExpire); err != nil {
		j.logAsync(&model.JWTLogItem{
			UserID:       &userID,
			Action:       "generate",
			TokenType:    "refresh",
			IPAddress:    ipAddress,
			UserAgent:    userAgent,
			Success:      true,
			ErrorMessage: fmt.Sprintf("缓存刷新令牌失败: %v", err),
			CreatedAt:    now,
		})
	}

	// 记录成功日志
	j.logAsync(&model.JWTLogItem{
		UserID:    &userID,
		Action:    "generate",
		TokenType: "access",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		CreatedAt: now,
	})

	j.logAsync(&model.JWTLogItem{
		UserID:    &userID,
		Action:    "generate",
		TokenType: "refresh",
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		CreatedAt: now,
	})

	return &model.JWTTokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresAt:    accessExpire,
	}, nil
}
