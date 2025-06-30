import React, { useEffect } from 'react';
import { useAuthStore } from '../../stores/authStore';

interface AppInitializerProps {
  children: React.ReactNode;
}

const AppInitializer: React.FC<AppInitializerProps> = ({ children }) => {
  const { initializeAuth } = useAuthStore();

  useEffect(() => {
    // 应用启动时初始化认证状态
    initializeAuth();
  }, [initializeAuth]);

  return <>{children}</>;
};

export default AppInitializer;