import { modules, allLevels, levelsOf, getLevel, getModule } from './levels.js';
import { store, escapeHtml, download, toast, RealLabAdapter } from './core.js';
import { mountSimulator } from './simulators.js';

const app = document.querySelector('#app');
let currentLevel = null;

function progress(moduleId) {
  const levels = levelsOf(moduleId);
  const done = levels.filter(l => store.data.completed[l.id]).length;
  return { done, total: levels.length, percent: Math.round(done / levels.length * 100) };
}
function updateBadge(){ document.querySelector('#mistakeCount').textContent=store.data.mistakes.length; }

function renderHome() {
  currentLevel=null;
  const done=Object.keys(store.data.completed).filter(id=>getLevel(id)).length;
  app.innerHTML=`
    <section class="hero">
      <div><div class="eyebrow">Interactive binary exploitation training</div><h1>从看见内存，<br>到<span>理解利用链</span>。</h1><p>面向 CTF Pwn 的本地交互训练平台。逐字节观察栈覆盖，验证格式化字符串读写，操纵现代 tcache，并跨越 Ring 0 理解内核提权。</p></div>
      <div class="hero-stats"><div class="stat"><strong>${done}<small style="font-size:13px;color:var(--muted)"> / ${allLevels.length}</small></strong><span>已完成训练</span><div class="progress-track"><div class="progress-fill" style="width:${done/allLevels.length*100}%"></div></div></div><div class="stat"><strong>${store.data.mistakes.length}</strong><span>待复习错误</span><div class="progress-track"><div class="progress-fill" style="width:${Math.min(store.data.mistakes.length*10,100)}%;background:var(--red)"></div></div></div></div>
    </section>
    <div class="section-heading"><h2>训练模块</h2><p>SELECT A MODULE TO BEGIN</p></div>
    <section class="module-grid">${modules.map(m=>{const p=progress(m.id);return `<button class="module-card" data-module="${m.id}" data-index="${m.index}" style="--accent:${m.accent}"><div class="module-top"><span class="module-code">${m.code}</span><span class="module-status">${p.done===p.total?'COMPLETED':p.done?'IN PROGRESS':'AVAILABLE'}</span></div><h3>${m.title}</h3><p>${m.description}</p><div class="module-meta"><span>${m.subtitle}</span><span>${p.done}/${p.total}</span></div><div class="progress-track"><div class="progress-fill" style="width:${p.percent}%"></div></div></button>`}).join('')}</section>
    <section class="workflow"><div class="workflow-title">真实比赛工作流<br>REAL EXPLOITATION LOOP</div><div class="workflow-steps"><span>信息收集</span><i>→</i><span>漏洞原语</span><i>→</i><span>泄露与利用</span><i>→</i><span>稳定验证</span><i>→</i><span>复盘归档</span></div></section>`;
  app.querySelectorAll('.module-card').forEach(btn=>btn.onclick=()=>renderModule(btn.dataset.module));
  updateBadge(); app.focus();
}

function renderModule(moduleId, levelId) {
  const module=getModule(moduleId), levels=levelsOf(moduleId);
  currentLevel=getLevel(levelId)||levels.find(l=>!store.data.completed[l.id])||levels[0];
  renderLevel(currentLevel, module);
}
function renderLevel(level,module) {
  currentLevel=level;
  const levels=levelsOf(module.id), idx=levels.findIndex(l=>l.id===level.id);
  app.innerHTML=`<div class="level-shell">
    <aside class="level-sidebar"><button class="back-button" id="backHome">← 返回训练模块</button><h2 style="color:${module.accent}">${module.title}</h2><p>${module.code} / ${levels.length} LEVELS</p><nav class="level-nav">${levels.map((l,i)=>`<button class="level-nav-button ${l.id===level.id?'active':''} ${store.data.completed[l.id]?'done':''}" data-level="${l.id}"><span class="level-number">${store.data.completed[l.id]?'✓':String(i+1).padStart(2,'0')}</span><span>${l.title}</span></button>`).join('')}</nav></aside>
    <section class="level-main"><header class="level-header"><div><div class="eyebrow">${module.code} / LEVEL ${String(level.number).padStart(2,'0')}</div><h1>${level.title}</h1><p>${level.objective}</p></div><span class="difficulty">[ ${level.difficulty} ]</span></header>
      <div class="objective"><strong>MISSION OBJECTIVE</strong>${level.objective}</div>
      <div class="workspace"><div class="panel"><div class="panel-title"><span>INTERACTIVE SIMULATOR</span><span>LOCAL / SAFE</span></div><div class="panel-body" id="simulator"></div><div id="result"></div></div>
      <aside><div class="panel"><div class="panel-title">TARGET SNAPSHOT <span>READ ONLY</span></div><div class="panel-body"><pre class="code-block">${colorCode(level.source)}</pre></div></div><div class="panel" style="margin-top:16px"><div class="panel-title">EXECUTION TRACE <button class="close-button" id="clearLog" title="清空日志">×</button></div><div class="console" id="console"><div class="log-line">模拟器就绪。所有操作仅影响本地虚拟状态。</div></div></div><div class="controls"><button class="secondary" id="hintBtn">获取提示 <span id="hintLevel">0/${level.hints.length}</span></button><button class="secondary" id="explainBtn">知识点</button></div><div id="hintArea"></div></aside></div>
      <div class="controls" style="justify-content:flex-end"><button class="secondary" id="prevBtn" ${idx===0?'disabled':''}>上一关</button><button class="secondary" id="nextBtn" ${idx===levels.length-1?'disabled':''}>下一关 →</button></div>
    </section></div>`;
  document.querySelector('#backHome').onclick=renderHome;
  app.querySelectorAll('.level-nav-button').forEach(btn=>btn.onclick=()=>renderLevel(getLevel(btn.dataset.level),module));
  document.querySelector('#prevBtn').onclick=()=>{if(idx>0)renderLevel(levels[idx-1],module);};
  document.querySelector('#nextBtn').onclick=()=>{if(idx<levels.length-1)renderLevel(levels[idx+1],module);};
  document.querySelector('#clearLog').onclick=clearLog;
  let hintIndex=0;
  document.querySelector('#hintBtn').onclick=()=>{
    if(hintIndex>=level.hints.length){toast('本关提示已全部显示');return;}
    const area=document.querySelector('#hintArea');
    const box=document.createElement('div');box.className='hint-box';box.innerHTML=`<strong>提示 ${hintIndex+1}</strong><br>${escapeHtml(level.hints[hintIndex])}`;area.appendChild(box);
    hintIndex++;store.hint(level.id);document.querySelector('#hintLevel').textContent=`${hintIndex}/${level.hints.length}`;
  };
  document.querySelector('#explainBtn').onclick=()=>showModal(`知识点 · ${level.title}`,`<p>${escapeHtml(level.explanation)}</p><h3>训练方法</h3><p>先独立构造并观察失败状态，再使用提示。通关后尝试不看答案回放利用链，并在错题本中记录错误原因。</p>`);
  mountSimulator(level,{log,pass:reason=>pass(level,reason),fail:reason=>fail(level,reason),clear:()=>{document.querySelector('#result').innerHTML='';}});
  app.focus();
}
function colorCode(source){return escapeHtml(source).replace(/(disabled|enabled|absent|Partial|Full|on|off)/g,'<span class="comment">$1</span>');}
function log(message,type=''){const con=document.querySelector('#console');if(!con)return;const line=document.createElement('div');line.className=`log-line ${type}`;line.textContent=message;con.appendChild(line);con.scrollTop=con.scrollHeight;}
function clearLog(){const con=document.querySelector('#console');if(con)con.innerHTML='<div class="log-line">执行日志已清空。</div>';}
function pass(level,explanation){
  if(document.querySelector('.result-banner.success'))return;
  store.complete(level.id);updateBadge();
  const levels=levelsOf(level.moduleId),idx=levels.findIndex(l=>l.id===level.id);
  document.querySelector('#result').innerHTML=`<div class="result-banner success"><strong>MISSION COMPLETED</strong><br>${escapeHtml(explanation)}${idx<levels.length-1?'<div class="controls"><button class="primary" id="continueBtn">进入下一关 →</button></div>':'<div class="controls"><button class="primary" id="continueBtn">返回模块</button></div>'}</div>`;
  document.querySelector('#continueBtn').onclick=()=>idx<levels.length-1?renderLevel(levels[idx+1],getModule(level.moduleId)):renderHome();
  const nav=document.querySelector(`.level-nav-button[data-level="${level.id}"]`);if(nav){nav.classList.add('done');nav.querySelector('.level-number').textContent='✓';}
  log('目标状态已达成，通关记录已保存。','success');toast('训练完成，进度已保存');
}
function fail(level,reason){
  store.mistake(level.id,level.title,reason);updateBadge();
  const result=document.querySelector('#result');if(result)result.innerHTML=`<div class="result-banner error"><strong>EXPLOIT FAILED</strong><br>${escapeHtml(reason)}<br><span style="color:var(--muted)">已加入错题本。可调整输入后重试，或逐级查看提示。</span></div>`;
  log(reason,'error');
}

function showModal(title,html){document.querySelector('#modalTitle').textContent=title;document.querySelector('#modalBody').innerHTML=html;document.querySelector('#modalBackdrop').classList.remove('hidden');}
function closeModal(){document.querySelector('#modalBackdrop').classList.add('hidden');}
document.querySelector('#closeModal').onclick=closeModal;
document.querySelector('#modalBackdrop').onclick=e=>{if(e.target.id==='modalBackdrop')closeModal();};
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
document.querySelector('#homeBtn').onclick=renderHome;
document.querySelector('#mistakesBtn').onclick=()=>{
  const items=store.data.mistakes;
  showModal('错题与复盘',items.length?`${items.map(m=>`<div class="mistake-item"><strong>${escapeHtml(m.title)}</strong><span>${escapeHtml(m.reason)}</span><br><small>${new Date(m.at).toLocaleString('zh-CN')}</small> <button class="secondary" style="padding:3px 8px;margin-left:8px" data-review="${m.levelId}">重新训练</button></div>`).join('')}<p>重新通关对应关卡后，该错误会自动标记为已解决。</p>`:'<div class="empty">暂无待复习错误。失败尝试会自动归档到这里。</div>');
  document.querySelectorAll('[data-review]').forEach(btn=>btn.onclick=()=>{const l=getLevel(btn.dataset.review);closeModal();renderLevel(l,getModule(l.moduleId));});
};
document.querySelector('#exportBtn').onclick=()=>{download(`pwnquest-progress-${new Date().toISOString().slice(0,10)}.json`,JSON.stringify({product:'PwnQuest Lab',version:1,exportedAt:new Date().toISOString(),...store.data},null,2));toast('学习进度已导出');};
document.querySelector('#labBtn').onclick=async()=>{
  const isLocalHost = ['127.0.0.1', 'localhost'].includes(location.hostname);
  if (!isLocalHost) {
    showModal('真实靶场模式','<h3>当前为纯 Web 教学版</h3><p>线上版本提供全部 20 个教学关卡、提示、错题本和进度导出，不连接访客设备上的任何本地服务。</p><p>真实 ELF 分析、GDB、Docker 与 QEMU 属于本地扩展能力。请通过使用指南获取源码并在自己的 Linux/WSL 环境中运行后端。</p>');
    return;
  }
  showModal('真实靶场模式','<div class="empty">正在检测本地实战后端...</div>');
  const status=await new RealLabAdapter().status();
  document.querySelector('#modalBody').innerHTML=`<h3>当前状态：${status.online?'<span style="color:var(--cyan)">后端已连接</span>':'<span style="color:var(--yellow)">Web 独立模式</span>'}</h3><p>${status.online?'可以开始导入真实 ELF 题目。':'当前未运行本地 FastAPI 后端，因此不会把模拟器结果标记为真实 ELF 验证。你仍可使用全部教学关卡。'}</p><h3>实战模式接口已预留</h3><ul><li><code>GET /api/health</code>：环境检测</li><li><code>POST /api/inspect</code>：ELF 保护与符号分析</li><li>后续扩展：真实进程、GDB、pwntools 和 Docker 验证</li></ul><p>实战后端仅应监听 <code>127.0.0.1</code>，真实二进制应在受限环境中运行。</p>`;
};

renderHome();
