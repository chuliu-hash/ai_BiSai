import { useMemo, useRef, useState } from 'react';
import { UploadCloud, FlaskConical, X, Loader2, Ban, ChevronLeft, ChevronRight } from 'lucide-react';
import { uploadAttack, attackNoDefense, attackWithShield } from '../api';

const CONCURRENCY = 4;      // 并发请求数
const PREVIEW_CAP = 200;    // 预览列表上限（防止 DOM 卡顿）
const RESULT_PAGE = 50;     // 结果表分页大小

export default function AttackView() {
  const fileRef = useRef(null);
  const [file, setFile] = useState(null);          // {name, size}
  const [prompts, setPrompts] = useState([]);      // 解析出的 prompt 列表（全量）
  const [parseInfo, setParseInfo] = useState(null);// {team, total, totalParsed, truncated, maxBatch}
  const [busy, setBusy] = useState(false);         // 解析中
  const [error, setError] = useState('');

  // 测试配置
  const [endpoint, setEndpoint] = useState('no_defense'); // no_defense | with_shield
  const [sensitivity, setSensitivity] = useState('low');
  const [enableRag, setEnableRag] = useState(false);

  // 测试结果：[{idx, prompt, ok, data, error, elapsed}]
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);
  const cancelRef = useRef(false);

  // 结果分页
  const [page, setPage] = useState(1);

  function reset() {
    setFile(null);
    setPrompts([]);
    setParseInfo(null);
    setError('');
    setResults([]);
    setPage(1);
    if (fileRef.current) fileRef.current.value = '';
  }

  async function onPick(f) {
    if (!f) return;
    setError('');
    setResults([]);
    setPage(1);
    setFile({ name: f.name, size: f.size });
    setBusy(true);
    try {
      const data = await uploadAttack(f, 0); // 0 = 不截断拿全量
      setPrompts(data.prompts || []);
      setParseInfo({
        team: data.team,
        total: data.total,
        totalParsed: data.total_parsed,
        truncated: data.truncated,
        maxBatch: data.max_batch,
      });
    } catch (e) {
      setError(e.message || '上传解析失败');
      setPrompts([]);
      setParseInfo(null);
    } finally {
      setBusy(false);
    }
  }

  function cancel() {
    cancelRef.current = true;
  }

  async function runTests() {
    if (!prompts.length || running) return;
    cancelRef.current = false;
    setRunning(true);
    setResults([]);
    setPage(1);

    // 把所有 idx 推入队列，按 CONCURRENCY 个一批并发
    // 捕获本次测试的 endpoint/sensitivity/enableRag，避免测试中途切换配置导致不一致
    const runEndpoint = endpoint;
    const runSensitivity = sensitivity;
    const runEnableRag = enableRag;
    const queue = prompts.map((p, i) => ({ idx: i + 1, prompt: p }));
    const out = new Array(queue.length);

    async function worker() {
      while (queue.length && !cancelRef.current) {
        const item = queue.shift();
        const start = performance.now();
        let entry = { ...item, endpoint: runEndpoint, ok: false, data: null, error: '', elapsed: 0 };
        try {
          const data = runEndpoint === 'no_defense'
            ? await attackNoDefense(item.prompt)
            : await attackWithShield(item.prompt, { sensitivity: runSensitivity, enableRag: runEnableRag });
          entry = { ...entry, ok: true, data, elapsed: performance.now() - start };
        } catch (e) {
          entry = { ...entry, error: e.message || '请求失败', elapsed: performance.now() - start };
        }
        out[item.idx - 1] = entry;
        // 流式追加（每次 worker 完成一条就更新一次）
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
    const blocked = results.filter((r) => r && (!r.ok || r.error || judge(r.data) === 'blocked')).length;
    const passed = results.filter((r) => r && r.ok && !r.error && judge(r.data) === 'safe').length;
    const errored = results.filter((r) => r && (!r.ok || r.error)).length;
    return { total: prompts.length, done, passed, blocked, errored };
  }, [results, prompts]);

  const progress = stats.total ? Math.round((stats.done / stats.total) * 100) : 0;

  // 结果分页切片
  const filled = results.filter(Boolean);
  const totalPages = Math.max(1, Math.ceil(filled.length / RESULT_PAGE));
  const curPage = Math.min(page, totalPages);
  const pageItems = filled.slice((curPage - 1) * RESULT_PAGE, curPage * RESULT_PAGE);

  return (
    <div className="pageStack">
      <div className="topbar">
        <div>
          <span className="eyebrow">Attack Track</span>
          <h1>攻击赛道 · 提交与测试</h1>
        </div>
      </div>

      {/* 上传区 */}
      <section className="panelCard">
        <div className="panelHeader">
          <UploadCloud size={20} />
          <h3>上传攻击语料（JSON）</h3>
        </div>

        <label className="uploadSurface" onDragOver={(e) => e.currentTarget.classList.add('drag')}
               onDragLeave={(e) => e.currentTarget.classList.remove('drag')}
               onDrop={(e) => { e.preventDefault(); e.currentTarget.classList.remove('drag'); if (e.dataTransfer.files?.[0]) onPick(e.dataTransfer.files[0]); }}>
          <UploadCloud size={32} />
          <strong>{file ? file.name : '点击或拖拽上传 JSON 文件'}</strong>
         
          <input ref={fileRef} type="file" accept=".json,application/json"
                 onChange={(e) => onPick(e.target.files?.[0])} />
        </label>


        {error && (
          <div className="statusBanner error" style={{ marginTop: 14 }}>
            <X size={18} />
            <div><strong>解析失败</strong><p>{error}</p></div>
          </div>
        )}

        {parseInfo && (
          <div className="statusBanner success" style={{ marginTop: 14 }}>
            <UploadCloud size={18} />
            <div>
              <strong>已解析 {parseInfo.total} 条攻击提示词{parseInfo.team ? `（来源：${parseInfo.team}）` : ''}</strong>
              {parseInfo.totalParsed > parseInfo.total && (
                <p>⚠ 文件实际含 {parseInfo.totalParsed} 条，已截取前 {parseInfo.total} 条。</p>
              )}
              {parseInfo.total > PREVIEW_CAP && (
                <p>ℹ 数量较多（{parseInfo.total} 条），下方预览仅显示前 {PREVIEW_CAP} 条，但全部参与测试。</p>
              )}
            </div>
          </div>
        )}
      </section>

      {/* 预览 + 测试配置 */}
      {prompts.length > 0 && (
        <section className="grid2">
          <div className="panelCard">
            <div className="panelHeader"><FlaskConical size={20} /><h3>测试配置</h3></div>

            <div style={{ display: 'grid', gap: 14 }}>
              <div>
                <span className="fieldLabel">测试端点</span>
                <select className="cyberSelect" value={endpoint} onChange={(e) => setEndpoint(e.target.value)}>
                  <option value="no_defense">无防护模型（/api/attack/no_defense）</option>
                  <option value="with_shield">模盾防护（/api/attack/with_shield）</option>
                </select>
              </div>

              {endpoint === 'with_shield' && (
                <>
                  <div>
                    <span className="fieldLabel">输入检测敏感度</span>
                    <select className="cyberSelect" value={sensitivity} onChange={(e) => setSensitivity(e.target.value)}>
                      <option value="low">low（低）</option>
                      <option value="medium">medium（中）</option>
                      <option value="high">high（高）</option>
                    </select>
                  </div>
                  <label className="toggleRow">
                    <input type="checkbox" className="switch" checked={enableRag}
                           onChange={(e) => setEnableRag(e.target.checked)} />
                    开启 RAG 安全上下文增强
                  </label>
                </>
              )}

              <div className="hintRow">
                并发 {CONCURRENCY} · 共 {prompts.length} 条 · 预计单条耗时取决于后端
              </div>

              <div className="actionRow">
                {!running ? (
                  <button type="button" className="primaryBtn" onClick={runTests}>
                    <FlaskConical size={16} />开始测试 {prompts.length} 条
                  </button>
                ) : (
                  <button type="button" className="ghostBtn" onClick={cancel}>
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
              <h3>提示词预览{prompts.length > PREVIEW_CAP ? `（前 ${PREVIEW_CAP} / ${prompts.length}）` : ''}</h3>
            </div>
            <div className="promptPreview">
              {prompts.slice(0, PREVIEW_CAP).map((p, i) => (
                <div className="row" key={i}><span className="idx">{i + 1}.</span><span className="txt">{p}</span></div>
              ))}
              {prompts.length > PREVIEW_CAP && (
                <div className="row moreHint">… 还有 {prompts.length - PREVIEW_CAP} 条未展示，全部参与测试</div>
              )}
            </div>
          </div>
        </section>
      )}

      {/* 统计 */}
      {(running || results.filter(Boolean).length > 0) && (
        <section className="statsGrid">
          <Stat label="总数" value={stats.total} />
          <Stat label="已测" value={stats.done} tone="cyan" />
          <Stat label="未被拦截" value={stats.passed} tone="green" />
          <Stat label="被拦截" value={stats.blocked} tone="red" />
          <Stat label="出错" value={stats.errored} tone="amber" />
        </section>
      )}

      {/* 结果表（分页） */}
      {filled.length > 0 && (
        <section className="panelCard">
          <div className="panelHeader">
            <FlaskConical size={20} />
            <h3>测试结果（共 {filled.length} 条）</h3>
            <div className="pager">
              <button type="button" className="ghostBtn pageBtn" onClick={() => setPage(curPage - 1)} disabled={curPage <= 1}>
                <ChevronLeft size={16} />
              </button>
              <span className="pageInfo">{curPage} / {totalPages}</span>
              <button type="button" className="ghostBtn pageBtn" onClick={() => setPage(curPage + 1)} disabled={curPage >= totalPages}>
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
          <div className="tableWrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>提示词</th>
                  <th>判定</th>
                  <th>模型回复 / 终止阶段</th>
                  <th>耗时</th>
                </tr>
              </thead>
              <tbody>
                {pageItems.map((r) => {
                  const j = judge(r.data);
                  return (
                    <tr key={r.idx}>
                      <td>{r.idx}</td>
                      <td className="cellPrompt">{r.prompt}</td>
                      <td>
                        {r.error ? <span className="toneTag amber">出错</span>
                          : j === 'safe' ? <span className="toneTag green">未拦截</span>
                          : <span className="toneTag red">已拦截</span>}
                      </td>
                      <td className="cellResp">
                        {r.error ? <span className="cellErr">{r.error}</span>
                          : renderResp(r.data, r.endpoint)}
                      </td>
                      <td>{r.elapsed ? `${(r.elapsed / 1000).toFixed(2)}s` : '-'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

// 判定单条结果：safe=未被拦截（通过），blocked=被拦截
function judge(data) {
  if (!data) return 'blocked';
  // with_shield：shield.is_safe=false 表示被拦截
  const sh = data.shield;
  if (sh && typeof sh.is_safe === 'boolean') {
    return sh.is_safe ? 'safe' : 'blocked';
  }
  // no_defense：没有 shield，按有无 model_response 判（有=未拦截）
  if (data.error) return 'blocked';
  return 'safe';
}

function renderResp(data, endpoint) {
  if (endpoint === 'with_shield') {
    const sh = data.shield || {};
    const stopped = sh.stopped_at;
    const resp = data.model_response;
    return (
      <>
        {stopped ? <span style={{ color: 'var(--amber)' }}>终止于 {stopped}</span>
                 : <span style={{ color: 'var(--green)' }}>全流程完成</span>}
        {resp ? <div style={{ marginTop: 4, color: 'var(--muted)' }}>{trunc(resp, 160)}</div> : null}
        {data.error ? <div className="cellErr" style={{ marginTop: 4 }}>{data.error}</div> : null}
      </>
    );
  }
  // no_defense
  return (
    <>
      {data.model_response ? <span>{trunc(data.model_response, 160)}</span>
                           : <span style={{ color: 'var(--muted-2)' }}>（空回复）</span>}
      {data.error ? <div className="cellErr" style={{ marginTop: 4 }}>{data.error}</div> : null}
    </>
  );
}

function Stat({ label, value, tone }) {
  return (
    <article className={`statCard ${tone || ''}`}>
      <span>{label}</span><strong>{value}</strong>
    </article>
  );
}

function trunc(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}
