import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuthStore } from '../../stores/authStore';
import styles from './styles.module.less';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading, token, setUser } = useAuthStore();
  const location = useLocation();

  useEffect(() => {
    // 如果有token但没有用户信息，尝试获取用户信息
    const initAuth = async () => {
      if (token && !isAuthenticated) {
        try {
          // 这里可以调用API获取用户信息
          // const userInfo = await authService.getCurrentUser();
          // setUser(userInfo);
          
          // 临时处理：如果有token就认为已认证
          // 实际项目中应该验证token有效性
          console.log('Token exists, user should be authenticated');
        } catch (error) {
          console.error('Failed to get user info:', error);
          // 如果获取用户信息失败，清除token
          useAuthStore.getState().logout();
        }
      }
    };

    initAuth();
  }, [token, isAuthenticated, setUser]);

  // 显示加载状态
  if (isLoading) {
    return (
      <div className={styles.loadingContainer}>
        <Spin size="large" tip="加载中..." />
      </div>
    );
  }

  // 如果未认证，重定向到登录页
  if (!isAuthenticated) {
    return (
      <Navigate 
        to="/login" 
        state={{ from: location.pathname }} 
        replace 
      />
    );
  }

  // 已认证，渲染子组件
  return <>{children}</>;
};

export default ProtectedRoute;