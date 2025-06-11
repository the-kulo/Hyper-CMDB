import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <div className="app">
        {/* 这里后续会添加路由 */}
        <h1>Hyper-CMDB</h1>
        <p>登录页面开发中...</p>
      </div>
    </ConfigProvider>
  );
}

export default App;
