import request from '../utils/request';
import type { LoginRequest, LoginResponse } from '../types/auth';

export const authService = {
  // 登录
  login: async (data: LoginRequest): Promise<LoginResponse> => {
    return request.post('/auth/login', data);
  },
  
  // 登出
  logout: async (): Promise<void> => {
    return request.post('/auth/logout');
  },
  
  // 获取当前用户信息
  getCurrentUser: async () => {
    return request.get('/auth/me');
  }
};