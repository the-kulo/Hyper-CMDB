import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import type { LocationState } from '../../types/router';

interface PublicRouteProps {
  children: React.ReactNode;
}

const PublicRoute: React.FC<PublicRouteProps> = ({ children }) => {
  const { isAuthenticated } = useAuthStore();
  const location = useLocation();
  
  // 获取重定向目标，默认为dashboard
  const from = (location.state as LocationState)?.from || '/dashboard';

  // 如果已经认证，重定向到目标页面
  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  // 未认证，显示公开页面（如登录页）
  return <>{children}</>;
};

export default PublicRoute;