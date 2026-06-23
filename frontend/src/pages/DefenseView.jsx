import { useEffect, useMemo, useRef, useState } from 'react';
import { UploadCloud, ShieldCheck, FlaskConical, X, Loader2, FileCode2, Ban } from 'lucide-react';
import { uploadDefense, uploadAttack, listGroups, detect } from '../api';

const CONCURRENCY = 6;   // 并发检测数（防御检测是纯规则，可以高一点）
const PREVIEW_CAP = 200; // 预览上限

export default function DefenseView() {
  // ── 防御包上传 ──
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);
  const [team, setTeam] = useState('');
  const [busy, setBusy] = useState(false);
  const [uploadInfo, setUploadInfo] = useState(null);
  const [error, setError] = useState('');

  // ── 队伍选择 ──
  const [groups, setGroups] = useState([]);
  const [selected, setSelected] = useState('');

  // ── 批量检测 ──
  const testFileRef = useRef(null);
  const [testFile, setTestFile] = useState(null);
  const [samples, setSamples] = useState([]);
  const [parseInfo, setParseInfo] = useState(null);
  const [parseError, setParseError] = useState('');
  const [parsing, setParsing] = useState(false);

  const [results, setResults] = useState([]);   // [{idx, sample, ok, verdict, error, elapsed}]
  const [running, setRunning] = useState(false);
  const cancelRef = useRef(false);

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

  // ── 防御包上传 ──
  function resetUpload() {
    setFile(null);
    setTeam('');
    setUploadInfo(null);
    setError('');
    if (fileRef.current) fileRef.current.value = '';
  }

  async function onPickZip(f) {
    if (!f) return;
    setError('');
    setUploadInfo(null);
    setFile(f);
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
      setGroups(data.groups || []);
      setSelected(data.team);
    } catch (e) {
      setError(e.message || '上传失败');
      setUploadInfo(null);
    } finally {
      setBusy(false);
    }
  }

  // ── 批量检测：上传 JSON 解析 prompt 列表 ──
  function resetTest() {
    setTestFile(null);
    setSamples([]);
    setParseInfo(null);
    setParseError('');
    setResults([]);
    if (testFileRef.current) testFileRef.current.value = '';
  }

  async function onPickJson(f) {
    if (!f) return;
    setParseError('');
    setResults([]);
    setTestFile({ name: f.name, size: f.size });
    setParsing(true);
    try {
      const data = await uploadAttack(f, 0); // 复用攻击端点的 JSON 解析（含 user_prompt/context/judge_rule）
      setSamples(data.samples || []);
      setParseInfo({ total: data.total, totalParsed: data.total_parsed, team: data.team });
    } catch (e) {
      setParseError(e.message || '解析失败');
      setSamples([]);
      setParseInfo(null);
    } finally {
      setParsing(false);
    }
  }

  async function runTests() {
    if (!samples.length || !selected || running) return;
    cancelRef.current = false;
    setRunning(true);
    setResults([]);

    const runTeam = selected;
    // 防御检测只检 user_prompt（context/judge_rule 与防御检测无关，丢弃）
    const queue = samples.map((s, i) => ({ idx: i + 1, sample: s, prompt: s.user_prompt }));
    const out = new Array(queue.length);

    async function worker() {
      while (queue.length && !cancelRef.current) {
        const item = queue.shift();
        const start = performance.now();
        let entry = { ...item, ok: false, verdict: null, error: '', elapsed: 0 };
        try {
          const verdict = await detect(runTeam, item.prompt);
          // Detect 接口约定返回 0/1；非 0/1（null/空/异常值）视作检测异常，标记为出错而非「不安全」
          if (verdict !== 0 && verdict !== 1) {
            throw new Error(`检测返回非法值: ${JSON.stringify(verdict)}`);
          }
          entry = { ...entry, ok: true, verdict, elapsed: performance.now() - start };
        } catch (e) {
          entry = { ...entry, error: e.message || '检测失败', elapsed: performance.now() - start };
        }
        out[item.idx - 1] = entry;
        setResults((prev) => {
          const next = prev.slice();
          next[item.idx - 1] = entry;
          return next;
        });
      }
    }

    const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker);
    await Promise.all(workers);
    setRunning(false);
  }

  // 统计
  const stats = useMemo(() => {
    const done = results.filter(Boolean).length;
    const safe = results.filter((r) => r && r.ok && !r.error && r.verdict === 0).length;
    const unsafe = results.filter((r) => r && r.ok && !r.error && r.verdict === 1).length;
    const errored = results.filter((r) => r && (!r.ok || r.error)).length;
    return { total: samples.length, done, safe, unsafe, errored };
  }, [results, samples]);

  const progress = stats.total ? Math.round((stats.done / stats.total) * 100) : 0;
  const filled = results.filter(Boolean);

  return (
    <div className="pageStack">
      <div className="topbar">
        <div>
          <span className="eyebrow">Defense Track</span>
          <h1>防御赛道 · 提交与批量检测</h1>
        </div>
      </div>

      {/* 防御包上传区 */}
      <section className="panelCard">
        <div className="panelHeader"><UploadCloud size={20} /><h3>上传防御方案（ZIP）</h3></div>

        <label className="uploadSurface" onDragOver={(e) => e.currentTarget.classList.add('drag')}
               onDragLeave={(e) => e.currentTarget.classList.remove('drag')}
               onDrop={(e) => { e.preventDefault(); e.currentTarget.classList.remove('drag'); const f = e.dataTransfer.files?.[0]; if (f) onPickZip(f); }}>
          <UploadCloud size={32} />
          <strong>{file ? file.name : '点击或拖拽上传 ZIP 压缩包'}</strong>
          <span>须暴露 Detect(user_prompt) → 0/1 接口</span>
          <input ref={fileRef} type="file" accept=".zip,application/zip"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) onPickZip(f); }} />
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
            <button type="button" className="ghostBtn" onClick={resetUpload} disabled={busy}><X size={16} />清空</button>
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

      {/* 批量检测区 */}
      <section className="panelCard">
        <div className="panelHeader"><FlaskConical size={20} /><h3>批量检测</h3></div>

        {/* 队伍选择 */}
        <div style={{ marginBottom: 14 }}>
          <span className="fieldLabel">选择队伍</span>
          <select className="cyberSelect" value={selected} onChange={(e) => setSelected(e.target.value)}>
            {groups.length === 0 && <option value="">（暂无队伍，请先上传）</option>}
            {groups.map((g) => <option key={g} value={g}>{g}</option>)}
          </select>
        </div>

        {/* 上传 JSON 检测语料 */}
        <label className="uploadSurface" onDragOver={(e) => e.currentTarget.classList.add('drag')}
               onDragLeave={(e) => e.currentTarget.classList.remove('drag')}
               onDrop={(e) => { e.preventDefault(); e.currentTarget.classList.remove('drag'); const f = e.dataTransfer.files?.[0]; if (f) onPickJson(f); }}>
          <UploadCloud size={32} />
          <strong>{testFile ? testFile.name : '点击或拖拽上传检测语料（JSON）'}</strong>
          <span>支持对象数组 / 字符串数组 / 按队分组 三种格式</span>
          <input ref={testFileRef} type="file" accept=".json,application/json"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) onPickJson(f); }} />
        </label>

        <div className="actionRow" style={{ marginTop: 14 }}>
          <button type="button" className="ghostBtn" onClick={() => testFileRef.current?.click()} disabled={parsing}>
            选择文件
          </button>
          {testFile && <button type="button" className="ghostBtn" onClick={resetTest} disabled={parsing}><X size={16} />清空</button>}
          {parsing && <span style={{ color: 'var(--muted)', fontSize: 13 }}><Loader2 size={14} className="spinner" style={{ marginRight: 6 }} />解析中…</span>}
        </div>

        {parseError && (
          <div className="statusBanner error" style={{ marginTop: 14 }}>
            <X size={18} /><div><strong>解析失败</strong><p>{parseError}</p></div>
          </div>
        )}

        {parseInfo && (
          <div className="statusBanner success" style={{ marginTop: 14 }}>
            <UploadCloud size={18} />
            <div>
              <strong>已解析 {parseInfo.total} 条检测提示词</strong>
              {parseInfo.totalParsed > parseInfo.total && (
                <p>⚠ 文件实际含 {parseInfo.totalParsed} 条，已截取前 {parseInfo.total} 条。</p>
              )}
              {parseInfo.total > PREVIEW_CAP && (
                <p>ℹ 数量较多（{parseInfo.total} 条），预览仅显示前 {PREVIEW_CAP} 条，全部参与检测。</p>
              )}
            </div>
          </div>
        )}
      </section>

      {/* 预览 + 检测控制 */}
      {samples.length > 0 && (
        <section className="grid2">
          <div className="panelCard">
            <div className="panelHeader"><FlaskConical size={20} /><h3>检测配置</h3></div>
            <div style={{ display: 'grid', gap: 14 }}>
              <div className="hintRow">
                队伍：<strong>{selected || '未选择'}</strong> · 并发 {CONCURRENCY} · 共 {samples.length} 条
              </div>
              <div className="actionRow">
                {!running ? (
                  <button type="button" className="primaryBtn" onClick={runTests} disabled={!selected}>
                    <FlaskConical size={16} />开始检测 {samples.length} 条
                  </button>
                ) : (
                  <button type="button" className="ghostBtn" onClick={() => { cancelRef.current = true; }}>
                    <Ban size={16} />取消（已测 {stats.done}/{stats.total}）
                  </button>
                )}
              </div>
              {(running || stats.done > 0) && (
                <div className="progressWrap">
                  <div className="progressBar"><div className="progressFill" style={{ width: `${progress}%` }} /></div>
                  <span className="progressTxt">{stats.done}/{stats.total} · {progress}%</span>
                </div>
              )}
            </div>
          </div>

          <div className="panelCard">
            <div className="panelHeader">
              <UploadCloud size={20} />
              <h3>提示词预览{samples.length > PREVIEW_CAP ? `（前 ${PREVIEW_CAP} / ${samples.length}）` : ''}</h3>
            </div>
            <div className="promptPreview">
              {samples.slice(0, PREVIEW_CAP).map((s, i) => (
                <div className="row" key={i}><span className="idx">{i + 1}.</span><span className="txt">{s.user_prompt}</span></div>
              ))}
              {samples.length > PREVIEW_CAP && (
                <div className="row moreHint">… 还有 {samples.length - PREVIEW_CAP} 条未展示，全部参与检测</div>
              )}
            </div>
          </div>
        </section>
      )}

      {/* 统计 */}
      {(running || filled.length > 0) && (
        <section className="statsGrid">
          <Stat label="总数" value={stats.total} />
          <Stat label="已测" value={stats.done} tone="cyan" />
          <Stat label="安全" value={stats.safe} tone="green" />
          <Stat label="不安全" value={stats.unsafe} tone="red" />
          <Stat label="出错" value={stats.errored} tone="amber" />
        </section>
      )}

      {/* 结果表 */}
      {filled.length > 0 && (
        <section className="panelCard">
          <div className="panelHeader">
            <FlaskConical size={20} />
            <h3>检测结果（共 {filled.length} 条）</h3>
          </div>
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>提示词</th>
                  <th>判定</th>
                  <th>耗时</th>
                </tr>
              </thead>
              <tbody>
                {filled.map((r) => (
                  <tr key={r.idx}>
                    <td>{r.idx}</td>
                    <td className="cellPrompt">{r.prompt}</td>
                    <td>
                      {r.error ? <span className="toneTag amber">出错</span>
                        : r.verdict === 0 ? <span className="toneTag green">安全（0）</span>
                        : <span className="toneTag red">不安全（1）</span>}
                      {r.error && <div className="cellErr" style={{ marginTop: 4 }}>{r.error}</div>}
                    </td>
                    <td>{r.elapsed ? `${(r.elapsed / 1000).toFixed(2)}s` : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function Stat({ label, value, tone }) {
  return (
    <article className={`statCard ${tone || ''}`}>
      <span>{label}</span><strong>{value}</strong>
    </article>
  );
}
