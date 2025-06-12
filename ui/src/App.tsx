import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import Login from './pages/login';

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <div className="app">
        <Login />
      </div>
    </ConfigProvider>
  );
}

export default App;
