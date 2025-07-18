import React, { useState } from 'react'
import { Card, Form, Input, Button, message, Layout } from 'antd'
import { UserOutlined, LockOutlined } from '@ant-design/icons'
import { useNavigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'
import type { LoginRequest } from '../../types/auth'
import type { LocationState } from '../../types/router'
import styles from './styles.module.less'

const { Content } = Layout

const LoginPage: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const { login } = useAuthStore()
  const [form] = Form.useForm()
  const navigate = useNavigate()
  const location = useLocation()
  
  // 获取重定向目标，默认为dashboard
  const from = (location.state as LocationState)?.from || '/dashboard'

  // 处理登录提交
  const handleLogin = async (values: LoginRequest) => {
    try {
      setLoading(true)
      await login(values.username, values.password)
      message.success('登录成功！')
      
      // 跳转到目标页面
      navigate(from, { replace: true })
    } catch {
      message.error('登录失败，请检查用户名和密码')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout className={styles.loginLayout}>
      <Content className={styles.loginContent}>
        <div className={styles.loginContainer}>
          <Card className={styles.loginCard}>
            {/* 页面标题 */}
            <div className={styles.loginHeader}>
              <h1 className={styles.title}>Hyper CMDB</h1>
              <p className={styles.subtitle}>多云配置管理系统</p>
            </div>

            {/* 登录表单 */}
            <Form
              form={form}
              name="login"
              onFinish={handleLogin}
              autoComplete="off"
              size="large"
            >
              <Form.Item
                name="username"
                rules={[
                  { required: true, message: '请输入用户名' },
                  { min: 3, message: '用户名至少3个字符' }
                ]}
              >
                <Input
                  prefix={<UserOutlined />}
                  placeholder="用户名"
                />
              </Form.Item>

              <Form.Item
                name="password"
                rules={[
                  { required: true, message: '请输入密码' },
                  { min: 6, message: '密码至少6个字符' }
                ]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="密码"
                />
              </Form.Item>

              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  block
                >
                  登录
                </Button>
              </Form.Item>
            </Form>
          </Card>
        </div>
      </Content>
    </Layout>
  )
}

export default LoginPage