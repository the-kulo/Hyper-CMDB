package response

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Response 统一响应结构
type Response struct {
	Code    int         `json:"code"`              // 响应码
	Message string      `json:"message"`           // 响应消息
	Data    interface{} `json:"data,omitempty"`    // 响应数据
	Error   string      `json:"error,omitempty"`   // 错误信息
	Time    int64       `json:"time"`              // 响应时间戳
}

// 响应码常量
const (
	CodeSuccess           = 200  // 成功
	CodeBadRequest        = 400  // 请求参数错误
	CodeUnauthorized      = 401  // 未认证
	CodeForbidden         = 403  // 权限不足
	CodeNotFound          = 404  // 资源不存在
	CodeMethodNotAllowed  = 405  // 方法不允许
	CodeConflict          = 409  // 资源冲突
	CodeTooManyRequests   = 429  // 请求过于频繁
	CodeInternalError     = 500  // 服务器内部错误
	CodeServiceUnavailable = 503  // 服务不可用
)

// Success 成功响应
func Success(c *gin.Context, message string, data interface{}) {
	response := Response{
		Code:    CodeSuccess,
		Message: message,
		Data:    data,
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusOK, response)
}

// BadRequest 请求参数错误
func BadRequest(c *gin.Context, message string) {
	response := Response{
		Code:    CodeBadRequest,
		Message: message,
		Error:   "请求参数错误",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusBadRequest, response)
}

// Unauthorized 未认证
func Unauthorized(c *gin.Context, message string) {
	response := Response{
		Code:    CodeUnauthorized,
		Message: message,
		Error:   "未认证",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusUnauthorized, response)
}

// Forbidden 权限不足
func Forbidden(c *gin.Context, message string) {
	response := Response{
		Code:    CodeForbidden,
		Message: message,
		Error:   "权限不足",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusForbidden, response)
}

// NotFound 资源不存在
func NotFound(c *gin.Context, message string) {
	response := Response{
		Code:    CodeNotFound,
		Message: message,
		Error:   "资源不存在",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusNotFound, response)
}

// MethodNotAllowed 方法不允许
func MethodNotAllowed(c *gin.Context, message string) {
	response := Response{
		Code:    CodeMethodNotAllowed,
		Message: message,
		Error:   "方法不允许",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusMethodNotAllowed, response)
}

// Conflict 资源冲突
func Conflict(c *gin.Context, message string) {
	response := Response{
		Code:    CodeConflict,
		Message: message,
		Error:   "资源冲突",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusConflict, response)
}

// TooManyRequests 请求过于频繁
func TooManyRequests(c *gin.Context, message string) {
	response := Response{
		Code:    CodeTooManyRequests,
		Message: message,
		Error:   "请求过于频繁",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusTooManyRequests, response)
}

// InternalServerError 服务器内部错误
func InternalServerError(c *gin.Context, message string) {
	response := Response{
		Code:    CodeInternalError,
		Message: message,
		Error:   "服务器内部错误",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusInternalServerError, response)
}

// ServiceUnavailable 服务不可用
func ServiceUnavailable(c *gin.Context, message string) {
	response := Response{
		Code:    CodeServiceUnavailable,
		Message: message,
		Error:   "服务不可用",
		Time:    getCurrentTimestamp(),
	}
	c.JSON(http.StatusServiceUnavailable, response)
}

// Error 通用错误响应
func Error(c *gin.Context, code int, message string, err error) {
	response := Response{
		Code:    code,
		Message: message,
		Time:    getCurrentTimestamp(),
	}

	if err != nil {
		response.Error = err.Error()
	}

	// 根据错误码设置HTTP状态码
	httpStatus := http.StatusInternalServerError
	switch code {
	case CodeSuccess:
		httpStatus = http.StatusOK
	case CodeBadRequest:
		httpStatus = http.StatusBadRequest
	case CodeUnauthorized:
		httpStatus = http.StatusUnauthorized
	case CodeForbidden:
		httpStatus = http.StatusForbidden
	case CodeNotFound:
		httpStatus = http.StatusNotFound
	case CodeMethodNotAllowed:
		httpStatus = http.StatusMethodNotAllowed
	case CodeConflict:
		httpStatus = http.StatusConflict
	case CodeTooManyRequests:
		httpStatus = http.StatusTooManyRequests
	case CodeServiceUnavailable:
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, response)
}

// SuccessWithPagination 带分页的成功响应
func SuccessWithPagination(c *gin.Context, message string, data interface{}, pagination *Pagination) {
	response := PaginationResponse{
		Response: Response{
			Code:    CodeSuccess,
			Message: message,
			Data:    data,
			Time:    getCurrentTimestamp(),
		},
		Pagination: pagination,
	}
	c.JSON(http.StatusOK, response)
}

// PaginationResponse 分页响应结构
type PaginationResponse struct {
	Response
	Pagination *Pagination `json:"pagination,omitempty"`
}

// Pagination 分页信息
type Pagination struct {
	Page       int   `json:"page"`        // 当前页码
	PageSize   int   `json:"page_size"`   // 每页大小
	Total      int64 `json:"total"`       // 总记录数
	TotalPages int   `json:"total_pages"` // 总页数
	HasNext    bool  `json:"has_next"`    // 是否有下一页
	HasPrev    bool  `json:"has_prev"`    // 是否有上一页
}

// NewPagination 创建分页信息
func NewPagination(page, pageSize int, total int64) *Pagination {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 10
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if totalPages <= 0 {
		totalPages = 1
	}

	return &Pagination{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}

// getCurrentTimestamp 获取当前时间戳（毫秒）
func getCurrentTimestamp() int64 {
	return getCurrentTime().UnixMilli()
}

// getCurrentTime 获取当前时间（可用于测试时mock）
var getCurrentTime = func() time.Time {
	return time.Now()
}

// ValidationError 验证错误响应
func ValidationError(c *gin.Context, errors map[string]string) {
	response := ValidationErrorResponse{
		Response: Response{
			Code:    CodeBadRequest,
			Message: "请求参数验证失败",
			Error:   "参数验证错误",
			Time:    getCurrentTimestamp(),
		},
		ValidationErrors: errors,
	}
	c.JSON(http.StatusBadRequest, response)
}

// ValidationErrorResponse 验证错误响应结构
type ValidationErrorResponse struct {
	Response
	ValidationErrors map[string]string `json:"validation_errors,omitempty"`
}

// AbortWithError 中断请求并返回错误
func AbortWithError(c *gin.Context, code int, message string, err error) {
	Error(c, code, message, err)
	c.Abort()
}

// AbortWithUnauthorized 中断请求并返回未认证错误
func AbortWithUnauthorized(c *gin.Context, message string) {
	Unauthorized(c, message)
	c.Abort()
}

// AbortWithForbidden 中断请求并返回权限不足错误
func AbortWithForbidden(c *gin.Context, message string) {
	Forbidden(c, message)
	c.Abort()
}

// AbortWithInternalError 中断请求并返回服务器内部错误
func AbortWithInternalError(c *gin.Context, message string) {
	InternalServerError(c, message)
	c.Abort()
}