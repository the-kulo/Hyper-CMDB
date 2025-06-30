import React from 'react';
import { Layout, Typography, Card, Space, Dropdown, Button } from 'antd';
import { UserOutlined, DatabaseOutlined, CloudOutlined, LogoutOutlined, DownOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import styles from './styles.module.less';

const { Content, Header } = Layout;
const { Title, Text } = Typography;

const Dashboard: React.FC = () => {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const userMenuItems = [
    {
      key: 'profile',
      label: '个人信息',
      icon: <UserOutlined />,
    },
    {
      type: 'divider' as const,
    },
    {
      key: 'logout',
      label: '退出登录',
      icon: <LogoutOutlined />,
      onClick: handleLogout,
    },
  ];

  return (
    <Layout className={styles.dashboardLayout}>
      <Header className={styles.header}>
        <div className={styles.headerContent}>
          <Title level={3} className={styles.title}>
            Hyper CMDB
          </Title>
          <div className={styles.userInfo}>
            <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
              <Button type="text" className={styles.userButton}>
                <UserOutlined className={styles.userIcon} />
                <Text className={styles.username}>
                  {user?.username || '用户'}
                </Text>
                <DownOutlined className={styles.dropdownIcon} />
              </Button>
            </Dropdown>
          </div>
        </div>
      </Header>
      
      <Content className={styles.content}>
        <div className={styles.container}>
          <div className={styles.welcomeSection}>
            <Title level={2} className={styles.welcomeTitle}>
              欢迎使用 Hyper CMDB
            </Title>
            <Text className={styles.welcomeText}>
              多云配置管理系统 - 统一管理您的云资源
            </Text>
          </div>

          <div className={styles.cardGrid}>
            <Card 
              className={styles.featureCard}
              hoverable
              cover={
                <div className={styles.cardIcon}>
                  <DatabaseOutlined />
                </div>
              }
            >
              <Card.Meta
                title="资源管理"
                description="统一管理和监控您的云资源配置"
              />
            </Card>

            <Card 
              className={styles.featureCard}
              hoverable
              cover={
                <div className={styles.cardIcon}>
                  <CloudOutlined />
                </div>
              }
            >
              <Card.Meta
                title="多云支持"
                description="支持阿里云、AWS、Azure等主流云平台"
              />
            </Card>

            <Card 
              className={styles.featureCard}
              hoverable
              cover={
                <div className={styles.cardIcon}>
                  <UserOutlined />
                </div>
              }
            >
              <Card.Meta
                title="权限管理"
                description="细粒度的用户权限和角色管理"
              />
            </Card>
          </div>

          <div className={styles.statusSection}>
            <Space direction="vertical" size="large" style={{ width: '100%' }}>
              <Card className={styles.statusCard}>
                <Title level={4}>系统状态</Title>
                <Text type="success">✓ 系统运行正常</Text>
              </Card>
              
              <Card className={styles.statusCard}>
                <Title level={4}>快速开始</Title>
                <Text>您可以开始配置和管理您的云资源了</Text>
              </Card>
            </Space>
          </div>
        </div>
      </Content>
    </Layout>
  );
};

export default Dashboard;