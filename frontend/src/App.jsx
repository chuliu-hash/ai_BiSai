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

  return (
    <div className="app-shell">
      <Sidebar active={tab} onSwitch={setTab} conn={conn} />
      <main className="main">
        {tab === 'attack' ? <AttackView /> : <DefenseView />}
      </main>
    </div>
  );
}
