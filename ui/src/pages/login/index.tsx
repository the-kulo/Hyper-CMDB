import React, { useState } from 'react'
import { Card, Form, Input, Button, message, Layout } from 'antd'
import { UserOutlined, LockOutlined } from '@ant-design/icons'
import { useAuthStore } from '../../stores/authStore'
import type { LoginRequest } from '../../types/auth'
import styles from './styles.module.less'

const { Content } = Layout

const LoginPage: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const { login } = useAuthStore()
  const [form] = Form.useForm()

  // 处理登录提交
  const handleLogin = async (values: LoginRequest) => {
    try {
      setLoading(true)
      await login(values.username, values.password)
      message.success('登录成功！')
       // 这里后续会添加路由跳转
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
                  placeholder="密码1"
                />
              </Form.Item>

              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  block
                >
                  登录1
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