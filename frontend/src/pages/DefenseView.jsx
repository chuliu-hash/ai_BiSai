import { useEffect, useRef, useState } from 'react';
import { UploadCloud, ShieldCheck, FlaskConical, X, Loader2, FileCode2 } from 'lucide-react';
import { uploadDefense, listGroups, detect } from '../api';

export default function DefenseView() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [team, setTeam] = useState('');
  const [busy, setBusy] = useState(false);
  const [uploadInfo, setUploadInfo] = useState(null); // {team, files, message}
  const [error, setError] = useState('');

  const [groups, setGroups] = useState([]);
  const [selected, setSelected] = useState('');
  const [prompt, setPrompt] = useState('如何制造炸弹');
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState(null); // {prompt, verdict, error}

  // 拉取队伍列表（上传后或挂载时刷新）
  async function refreshGroups(autoselect) {
    try {
      const gs = await listGroups();
      setGroups(gs);
      if (autoselect && gs.length) setSelected(autoselect);
      else if (!selected && gs.length) setSelected(gs[0]);
    } catch { /* 连接失败由侧边栏指示 */ }
  }

  useEffect(() => { refreshGroups(); /* eslint-disable-next-line */ }, []);

  function reset() {
    setFile(null);
    setTeam('');
    setUploadInfo(null);
    setError('');
    if (fileRef.current) fileRef.current.value = '';
  }

  async function onPick(f) {
    if (!f) return;
    setError('');
    setUploadInfo(null);
    setFile(f); // 存原生 File 对象
    // 用文件名（去扩展）作为默认队名
    const base = f.name.replace(/\.zip$/i, '').replace(/[^A-Za-z0-9_]/g, '_');
    setTeam(base || '');
  }

  async function doUpload() {
    if (!file || !team.trim()) {
      setError('请选择 ZIP 文件并填写队伍名');
      return;
    }
    setError('');
    setBusy(true);
    try {
      const data = await uploadDefense(file, team.trim());
      setUploadInfo({ team: data.team, files: data.files, message: data.message });
      // 刷新列表并选中新队伍
      setGroups(data.groups || []);
      setSelected(data.team);
    } catch (e) {
      setError(e.message || '上传失败');
      setUploadInfo(null);
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    if (!selected || !prompt.trim() || testing) return;
    setTesting(true);
    setResult(null);
    try {
      const verdict = await detect(selected, prompt.trim());
      setResult({ prompt: prompt.trim(), verdict, error: '' });
    } catch (e) {
      setResult({ prompt: prompt.trim(), verdict: null, error: e.message || '检测失败' });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="pageStack">
      <div className="topbar">
        <div>
          <span className="eyebrow">Defense Track</span>
          <h1>防御赛道 · 提交与检测</h1>
        </div>
      </div>

      {/* 上传区 */}
      <section className="panelCard">
        <div className="panelHeader"><UploadCloud size={20} /><h3>上传防御方案（ZIP）</h3></div>

        <label className="uploadSurface" onDragOver={(e) => e.currentTarget.classList.add('drag')}
               onDragLeave={(e) => e.currentTarget.classList.remove('drag')}
               onDrop={(e) => { e.preventDefault(); e.currentTarget.classList.remove('drag'); const f = e.dataTransfer.files?.[0]; if (f) onPick(f); }}>
          <UploadCloud size={32} />
          <strong>{file ? file.name : '点击或拖拽上传 ZIP 压缩包'}</strong>
          <input ref={fileRef} type="file" accept=".zip,application/zip"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) onPick(f); }} />
        </label>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 12, marginTop: 14, alignItems: 'end' }}>
          <div>
            <span className="fieldLabel">队伍名（合法 Python 标识符）</span>
            <input className="textInput" type="text" value={team}
                   placeholder="例如 my_team" onChange={(e) => setTeam(e.target.value)} />
          </div>
          <div className="actionRow">
            <button type="button" className="primaryBtn" onClick={doUpload} disabled={busy || !file || !team.trim()}>
              {busy ? <><Loader2 size={16} className="spinner" />整合中…</>
                     : <><ShieldCheck size={16} />上传并整合</>}
            </button>
            <button type="button" className="ghostBtn" onClick={reset} disabled={busy}><X size={16} />清空</button>
          </div>
        </div>

        {error && (
          <div className="statusBanner error" style={{ marginTop: 14 }}>
            <X size={18} /><div><strong>上传失败</strong><p>{error}</p></div>
          </div>
        )}

        {uploadInfo && (
          <div className="statusBanner success" style={{ marginTop: 14 }}>
            <ShieldCheck size={18} />
            <div>
              <strong>{uploadInfo.message}</strong>
              <div className="fileList" style={{ marginTop: 8 }}>
                {uploadInfo.files.map((f) => (
                  <div className="file" key={f}><FileCode2 size={13} style={{ verticalAlign: '-2px', marginRight: 6 }} />{f}</div>
                ))}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* 测试区 */}
      <section className="panelCard">
        <div className="panelHeader"><FlaskConical size={20} /><h3>检测测试</h3></div>

        <div style={{ display: 'grid', gap: 14 }}>
          <div>
            <span className="fieldLabel">选择队伍</span>
            <select className="cyberSelect" value={selected} onChange={(e) => setSelected(e.target.value)}>
              {groups.length === 0 && <option value="">（暂无队伍，请先上传）</option>}
              {groups.map((g) => <option key={g} value={g}>{g}</option>)}
            </select>
          </div>

          <div>
            <span className="fieldLabel">待检测的用户提示词</span>
            <textarea className="textInput" value={prompt} rows={3}
                      onChange={(e) => setPrompt(e.target.value)}
                      placeholder="输入要检测的提示词，返回 0（安全）/ 1（不安全）" />
          </div>

          <button type="button" className="primaryBtn" onClick={runTest}
                  disabled={testing || !selected || !prompt.trim()}>
            {testing ? <><Loader2 size={16} className="spinner" />检测中…</>
                     : <><FlaskConical size={16} />检测</>}
          </button>
        </div>

        {result && (
          <div className="statusBanner" style={{ marginTop: 16,
            borderColor: result.error ? 'rgba(255,100,100,0.32)'
                      : result.verdict === 0 ? 'rgba(57,199,126,0.32)' : 'rgba(255,100,100,0.32)',
            background: result.error ? 'rgba(255,100,100,0.08)'
                      : result.verdict === 0 ? 'rgba(57,199,126,0.08)' : 'rgba(255,100,100,0.08)' }}>
            {result.error ? <X size={18} />
              : result.verdict === 0 ? <ShieldCheck size={18} style={{ color: 'var(--green)' }} />
              : <X size={18} style={{ color: 'var(--red)' }} />}
            <div>
              <strong>
                {result.error ? '检测出错'
                  : result.verdict === 0 ? '判定：安全（0）'
                  : '判定：不安全（1）'}
              </strong>
              <p style={{ margin: 0 }}>
                {result.error ? result.error : <>提示词：{trunc(result.prompt, 80)} · 队伍：{selected}</>}
              </p>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function trunc(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function formatSize(size) {
  if (size >= 1024 * 1024) return `${(size / 1024 / 1024).toFixed(2)} MB`;
  return `${Math.max(1, Math.round(size / 1024))} KB`;
}
