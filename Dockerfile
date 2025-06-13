# 多阶段构建
FROM node:20-alpine AS frontend-builder

WORKDIR /app/ui
COPY ui/package*.json ./
RUN npm ci

COPY ui/ ./
RUN npm run build

# Go构建阶段
FROM golang:1.24.2-alpine AS backend-builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o hyper-cmdb ./cmd

# 最终运行镜像
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

# 复制后端二进制文件
COPY --from=backend-builder /app/hyper-cmdb .

# 复制前端构建文件
COPY --from=frontend-builder /app/ui/dist ./static

# 复制配置文件
COPY config/ ./config/

EXPOSE 8080

CMD ["./hyper-cmdb"]