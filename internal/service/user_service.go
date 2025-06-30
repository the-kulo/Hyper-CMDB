package service

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"h-cmdb/internal/model"
)

// UserService 用户服务接口
type UserService interface {
	ValidateCredentials(username, password string) (*model.User, error)
	GetUserByID(userID uint) (*model.User, error)
	GetUserByUsername(username string) (*model.User, error)
}

// userService 用户服务实现
type userService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务
func NewUserService(db *gorm.DB) UserService {
	return &userService{
		db: db,
	}
}

// ValidateCredentials 验证用户凭据
func (s *userService) ValidateCredentials(username, password string) (*model.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("用户名和密码不能为空")
	}

	// 查找用户
	var user model.User
	result := s.db.Preload("Roles").Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %w", result.Error)
	}

	// 检查用户状态
	if user.Status != model.UserStatusActive {
		return nil, errors.New("用户账号已被禁用")
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("密码错误")
	}

	return &user, nil
}

// GetUserByID 根据ID获取用户
func (s *userService) GetUserByID(userID uint) (*model.User, error) {
	var user model.User
	result := s.db.Preload("Roles").Where("id = ?", userID).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %w", result.Error)
	}

	return &user, nil
}

// GetUserByUsername 根据用户名获取用户
func (s *userService) GetUserByUsername(username string) (*model.User, error) {
	var user model.User
	result := s.db.Preload("Roles").Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("用户不存在")
		}
		return nil, fmt.Errorf("查询用户失败: %w", result.Error)
	}

	return &user, nil
}