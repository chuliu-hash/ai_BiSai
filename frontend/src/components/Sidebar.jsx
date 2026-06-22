import { Swords, ShieldCheck } from 'lucide-react';

const TABS = [
  { key: 'attack', label: '攻击赛道', icon: Swords, desc: '上传攻击语料 · 测试' },
  { key: 'defense', label: '防御赛道', icon: ShieldCheck, desc: '上传防御方案 · 检测' },
];

export default function Sidebar({ active, onSwitch, conn }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brandMark"><ShieldCheck size={18} /></div>
        <div>
          <strong>大模型攻防赛平台</strong>
          <span>LLM Security Arena</span>
        </div>
      </div>

      <nav className="sideNav" aria-label="赛道切换">
        {TABS.map(({ key, label, icon: Icon, desc }) => (
          <button
            key={key}
            type="button"
            className={active === key ? 'navItem active' : 'navItem'}
            onClick={() => onSwitch(key)}
          >
            <Icon size={18} />
            <span>
              <strong style={{ display: 'block', fontSize: 14 }}>{label}</strong>
              <em style={{ fontStyle: 'normal', fontSize: 11, color: 'var(--muted-2)' }}>{desc}</em>
            </span>
          </button>
        ))}
      </nav>

      <div className="connStatusCard">
        <span className={`connDot ${conn === 'ok' ? 'ok' : conn === 'err' ? 'err' : ''}`} />
        <span>
          {conn === 'ok' ? '后端已连接' : conn === 'err' ? '后端未连接' : '检测后端中…'}
        </span>
      </div>
    </aside>
  );
}
