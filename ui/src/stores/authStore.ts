import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { authService } from '../services/auth';
import type { User } from '../types/auth';

// 定义认证状态的接口
interface AuthState {
  user: User | null;           // 当前登录用户信息
  token: string | null;        // 认证令牌
  isLoading: boolean;          // 加载状态
  isAuthenticated: boolean;    // 认证状态
  login: (username: string, password: string) => Promise<void>;  // 登录方法
  logout: () => void;          // 登出方法
  setUser: (user: User) => void;  // 设置用户信息方法
  initializeAuth: () => void;  // 初始化认证状态方法
}

// 创建Zustand状态管理store
export const useAuthStore = create<AuthState>()(persist(
  (set) => ({
    // 初始状态
    user: null,
    token: null,
    isLoading: false,
    isAuthenticated: false,

    // 登录方法
    login: async (username: string, password: string) => {
      set({ isLoading: true });
      try {
        const response = await authService.login({ username, password });
        set({
          user: response.user,
          token: response.token,
          isLoading: false,
          isAuthenticated: true
        });
        localStorage.setItem('token', response.token);
      } catch (error) {
        set({ isLoading: false });
        throw error;
      }
    },

    // 登出方法
    logout: () => {
      set({ user: null, token: null, isAuthenticated: false });
      localStorage.removeItem('token');
    },

    // 设置用户信息方法
    setUser: (user: User) => set({ user }),

    // 初始化认证状态方法
    initializeAuth: () => {
      const token = localStorage.getItem('token');
      if (token) {
        // 如果有token，设置为已认证状态
        // 实际项目中应该验证token有效性
        set({ token, isAuthenticated: true });
      }
    }
  }),
  {
    name: 'auth-storage',
    partialize: (state) => ({ token: state.token, user: state.user })
  }
));