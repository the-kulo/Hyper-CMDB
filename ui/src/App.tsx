import { ConfigProvider } from 'antd';
import { RouterProvider } from 'react-router-dom';
import zhCN from 'antd/locale/zh_CN';
import router from './router';
import AppInitializer from './components/AppInitializer';
import './App.css';

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <AppInitializer>
        <div className="App">
          <RouterProvider router={router} />
        </div>
      </AppInitializer>
    </ConfigProvider>
  );
}

export default App;
