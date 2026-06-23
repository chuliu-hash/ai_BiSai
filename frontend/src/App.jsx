import { useCallback, useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import AttackView from './pages/AttackView';
import DefenseView from './pages/DefenseView';
import { health } from './api';

export default function App() {
  const [tab, setTab] = useState('attack');   // attack | defense
  const [conn, setConn] = useState('checking'); // ok | err | checking

  // 探测后端连接状态
  const checkConn = useCallback(async () => {
    setConn('checking');
    try {
      await health();
      setConn('ok');
    } catch {
      setConn('err');
    }
  }, []);

  useEffect(() => {
    checkConn();
    // 定期复探，保持连接指示准确
    const id = setInterval(checkConn, 8000);
    return () => clearInterval(id);
  }, [checkConn]);

  // 两个页面始终挂载，仅通过 CSS 隐藏未激活页：
  // 这样切换赛道时，正在进行的批量检测（worker）、已产出的结果、上传的文件、
  // 结果分页等内部状态都会保留，不会被卸载清空。
  return (
    <div className="app-shell">
      <Sidebar active={tab} onSwitch={setTab} conn={conn} />
      <main className="main">
        <div className={tab === 'attack' ? 'pagePane active' : 'pagePane'}>
          <AttackView />
        </div>
        <div className={tab === 'defense' ? 'pagePane active' : 'pagePane'}>
          <DefenseView />
        </div>
      </main>
    </div>
  );
}
