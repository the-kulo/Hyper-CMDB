package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"h-cmdb/internal/api/auth"
	"h-cmdb/internal/config"
	"h-cmdb/internal/database"
	"h-cmdb/internal/middleware"
	"h-cmdb/internal/service"
)

// Application 应用程序结构体
type Application struct {
	dbManager   *database.DatabaseManager
	jwtService  service.JWTService
	userService service.UserService
	server      *http.Server
}

func main() {
	// 设置Gin模式
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	// 创建应用程序实例
	app, err := NewApplication()
	if err != nil {
		log.Fatalf("创建应用程序失败: %v", err)
	}

	// 启动应用程序
	if err := app.Start(); err != nil {
		log.Fatalf("启动应用程序失败: %v", err)
	}

	// 等待中断信号
	app.WaitForShutdown()

	// 关闭应用程序
	if err := app.Shutdown(); err != nil {
		log.Printf("关闭应用程序时发生错误: %v", err)
	}

	log.Println("应用程序已安全关闭")
}

// NewApplication 创建新的应用程序实例
func NewApplication() (*Application, error) {
	// 加载环境变量
	if err := godotenv.Load(); err != nil {
		log.Printf("警告: 无法加载.env文件: %v", err)
	}

	// 初始化数据库管理器
	dbManager, err := database.NewDatabaseManager()
	if err != nil {
		return nil, fmt.Errorf("初始化数据库管理器失败: %w", err)
	}

	// 自动迁移数据库
	if err := dbManager.AutoMigrate(); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	// 加载JWT配置
	jwtConfig, err := config.LoadJWTConfig()
	if err != nil {
		return nil, fmt.Errorf("加载JWT配置失败: %w", err)
	}

	// 创建JWT服务
	jwtService := service.NewJWTService(jwtConfig, dbManager.DB, dbManager.Redis)

	// 创建用户服务
	userService := service.NewUserService(dbManager.DB)

	return &Application{
		dbManager:   dbManager,
		jwtService:  jwtService,
		userService: userService,
	}, nil
}

// Start 启动应用程序
func (app *Application) Start() error {
	// 创建Gin路由器
	router := gin.New()

	// 添加中间件
	app.setupMiddleware(router)

	// 设置路由
	app.setupRoutes(router)

	// 创建HTTP服务器
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	app.server = &http.Server{
		Addr:           ":" + port,
		Handler:        router,
		ReadTimeout:    time.Second * 30,
		WriteTimeout:   time.Second * 30,
		IdleTimeout:    time.Second * 60,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// 启动服务器
	log.Printf("服务器启动在端口 %s", port)
	go func() {
		if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	return nil
}

// setupMiddleware 设置中间件
func (app *Application) setupMiddleware(router *gin.Engine) {
	// 恢复中间件
	router.Use(gin.Recovery())

	// 日志中间件
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	// CORS中间件
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// 安全头中间件
	router.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Next()
	})
}

// setupRoutes 设置路由
func (app *Application) setupRoutes(router *gin.Engine) {
	// 健康检查
	router.GET("/health", app.healthCheck)

	// API路由组
	api := router.Group("/api")
	{
		// 创建JWT中间件
		jwtMiddleware := middleware.NewJWTMiddleware(app.jwtService)

		// 认证相关路由
		authController := auth.NewJWTController(app.jwtService, app.userService)
		authController.RegisterRoutes(api, jwtMiddleware)

		// 其他API路由可以在这里添加
		// 例如：
		// v1 := api.Group("/v1")
		// v1.Use(jwtMiddleware.AuthRequired())
		// {
		//     // 用户管理
		//     userController.RegisterRoutes(v1)
		//     // 角色管理
		//     roleController.RegisterRoutes(v1)
		//     // 云资源管理
		//     cloudController.RegisterRoutes(v1)
		// }
	}

	// 静态文件服务（如果需要）
	// router.Static("/static", "./static")
	// router.StaticFile("/favicon.ico", "./static/favicon.ico")
}

// healthCheck 健康检查处理器
func (app *Application) healthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// 检查数据库连接
	if err := app.dbManager.HealthCheck(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "unhealthy",
			"error":  err.Error(),
			"time":   time.Now().Unix(),
		})
		return
	}

	// 获取数据库统计信息
	stats, err := app.dbManager.GetStats()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Unix(),
			"error":  fmt.Sprintf("获取统计信息失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now().Unix(),
		"stats":  stats,
	})
}

// WaitForShutdown 等待关闭信号
func (app *Application) WaitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("收到关闭信号，开始优雅关闭...")
}

// Shutdown 关闭应用程序
func (app *Application) Shutdown() error {
	var errors []error

	// 关闭HTTP服务器
	if app.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		log.Println("关闭HTTP服务器...")
		if err := app.server.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("关闭HTTP服务器失败: %w", err))
		}
	}

	// 关闭JWT服务
	if app.jwtService != nil {
		log.Println("关闭JWT服务...")
		if jwtSvc, ok := app.jwtService.(interface{ Close() error }); ok {
			if err := jwtSvc.Close(); err != nil {
				errors = append(errors, fmt.Errorf("关闭JWT服务失败: %w", err))
			}
		}
	}

	// 关闭数据库连接
	if app.dbManager != nil {
		log.Println("关闭数据库连接...")
		if err := app.dbManager.Close(); err != nil {
			errors = append(errors, fmt.Errorf("关闭数据库连接失败: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("关闭应用程序时发生错误: %v", errors)
	}

	return nil
}