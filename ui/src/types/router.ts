// 路由相关的类型定义

// 路由状态接口
export interface LocationState {
  from?: string;
  [key: string]: unknown;
}

// 导航选项接口
export interface NavigateOptions {
  replace?: boolean;
  state?: LocationState;
}