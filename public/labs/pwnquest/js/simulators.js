import { escapeHtml, formatHex, littleEndian, parseHex } from './core.js';

export function mountSimulator(level, api) {
  const host = document.querySelector('#simulator');
  if (level.kind === 'quiz') mountQuiz(level, host, api);
  else if (level.kind === 'calc') mountCalc(level, host, api);
  else if (level.kind === 'stack' || level.kind === 'canary') mountStack(level, host, api);
  else if (level.kind === 'rop') mountChain(level, host, api);
  else if (level.kind === 'format') mountFormat(level, host, api);
  else if (level.kind === 'kernelCred') mountCred(level, host, api);
}

function question(level) { return `<div class="field"><label>${escapeHtml(level.question || '构造利用输入')}</label></div>`; }
function mountQuiz(level, host, api) {
  let selected = -1;
  host.innerHTML = `${question(level)}<div class="option-list">${level.options.map((o,i)=>`<button class="option-button" data-i="${i}"><b>${String.fromCharCode(65+i)}.</b> ${escapeHtml(o)}</button>`).join('')}</div><div class="controls"><button class="primary" id="runBtn" disabled>验证路线</button><button class="secondary" id="resetBtn">重置</button></div>`;
  const buttons = [...host.querySelectorAll('.option-button')];
  buttons.forEach(btn => btn.onclick = () => {
    selected = Number(btn.dataset.i);
    buttons.forEach(b => b.classList.toggle('selected', b === btn));
    host.querySelector('#runBtn').disabled = false;
  });
  host.querySelector('#runBtn').onclick = () => {
    buttons.forEach(b => b.classList.remove('correct','wrong'));
    if (selected === level.answer) {
      buttons[selected].classList.add('correct');
      api.log('路线检查通过：保护条件与利用原语可以闭合。','success');
      api.pass(level.explanation);
    } else {
      buttons[selected].classList.add('wrong'); buttons[level.answer].classList.add('correct');
      const reason = `选择了路线 ${String.fromCharCode(65+selected)}，它与当前保护或漏洞条件不匹配。`;
      api.log(reason,'error'); api.fail(reason);
    }
  };
  host.querySelector('#resetBtn').onclick = () => { selected=-1; buttons.forEach(b=>b.className='option-button'); host.querySelector('#runBtn').disabled=true; api.clear(); };
}

function mountCalc(level, host, api) {
  host.innerHTML = `${question(level)}<div class="field"><label>计算结果 <span>支持 0x 前缀</span></label><input id="calcInput" autocomplete="off" spellcheck="false" placeholder="${level.placeholder || '0x...'}"></div><div class="registers"><div class="register">已知运行时值<b>${escapeHtml(level.source.split('\n')[1] || '')}</b></div><div class="register">运算模型<b>${level.id==='h3'?'next = encoded ^ (pos >> 12)':'base = leaked - offset'}</b></div></div><div class="controls"><button class="primary" id="runBtn">提交计算</button><button class="secondary" id="resetBtn">清空</button></div>`;
  const input = host.querySelector('#calcInput');
  input.onkeydown = e => { if(e.key==='Enter') host.querySelector('#runBtn').click(); };
  host.querySelector('#runBtn').onclick = () => {
    try {
      const actual = parseHex(input.value), expected = parseHex(level.answer);
      if (actual === expected) { api.log(`地址计算正确：${formatHex(actual)}`,'success'); api.pass(level.explanation); }
      else {
        const reason = actual > expected ? '结果偏大：检查是否错误地做了加法，或偏移是否匹配。' : '结果偏小：重新核对符号偏移与借位运算。';
        api.log(`计算结果 ${formatHex(actual)} 与目标不一致。`,'error'); api.fail(reason);
      }
    } catch(e) { api.fail(e.message); }
  };
  host.querySelector('#resetBtn').onclick=()=>{input.value='';api.clear();};
}

function stackRows(level, values = {}) {
  const target = level.target;
  const rows = [
    ['高地址', values.rip || '0x0000000000000000','RIP / return'],
    ['+0x28', values.rbp || '0x0000000000000000','saved rbp'],
    ['+0x20', values.canary || 'AAAAAAAAAAAAAAAA','buffer 末尾'],
    ['+0x10', values.buf1 || '4141414141414141','buf + 16'],
    ['低地址', values.buf0 || '4141414141414141','buf']
  ];
  if (level.kind === 'canary') rows.splice(2,0,['+0x20',values.canaryValue||'canary ?','stack canary']);
  return `<div class="memory-grid">${rows.map(([addr,val,label])=>{
    const cls = label==='RIP / return'&&values.control?'control':label==='RIP / return'&&values.success?'success':label.includes('canary')&&values.canaryValue?'overwrite':'';
    return `<div class="memory-row"><span class="memory-address">${addr}</span><span class="memory-cell ${cls}">${escapeHtml(val)}</span><span class="memory-label">${label}</span></div>`;
  }).join('')}</div>`;
}
function mountStack(level, host, api) {
  const isCanary = level.kind === 'canary';
  host.innerHTML = `${question(level)}${stackRows(level)}<div class="field"><label>${isCanary?'buf → Canary 的 padding':'buf → 返回地址的 padding'} <span>十进制字节数</span></label><input id="paddingInput" inputmode="numeric" value="${isCanary?'24':'40'}"></div>${isCanary?`<div class="field"><label>泄露的 Canary <span>原值写回</span></label><input id="canaryInput" placeholder="0x..."></div>`:''}<div class="field"><label>目标返回地址 <span>win</span></label><input id="targetInput" placeholder="0x401256"></div><div class="controls"><button class="primary" id="runBtn">发送 payload</button><button class="secondary" id="resetBtn">重置栈帧</button></div><div id="bytePreview" class="hint-box hidden"></div>`;
  host.querySelector('#runBtn').onclick = () => {
    const padding = Number(host.querySelector('#paddingInput').value);
    let address, canary;
    try { address = parseHex(host.querySelector('#targetInput').value); if(isCanary) canary=parseHex(host.querySelector('#canaryInput').value); }
    catch(e){ api.fail(e.message); return; }
    const expectedPadding = isCanary ? 24 : level.buffer + level.saved;
    const expectedCanary = isCanary ? parseHex(level.canary) : 0n;
    const bytes = littleEndian(address);
    host.querySelector('#bytePreview').classList.remove('hidden');
    host.querySelector('#bytePreview').textContent = `返回地址的小端字节序列：${bytes}`;
    api.log(`输入长度检查：padding=${padding}，目标地址=${formatHex(address)}`);
    if (padding < expectedPadding) { api.fail(`还差 ${expectedPadding-padding} 字节才覆盖到${isCanary?'Canary':'返回地址'}，当前输入无法控制 RIP。`); return; }
    if (padding > expectedPadding) { api.fail(`padding 多出 ${padding-expectedPadding} 字节，关键结构的位置发生错位。`); return; }
    if (isCanary && canary !== expectedCanary) { api.fail('__stack_chk_fail：Canary 与泄露原值不一致，程序在返回前终止。'); return; }
    if (address !== parseHex(level.target)) { api.fail(`RIP=${formatHex(address)}，目标不是 win，触发 SIGSEGV。`); return; }
    const view = host.querySelector('.memory-grid');
    view.outerHTML = stackRows(level,{rip:littleEndian(address),control:true,canaryValue:isCanary?littleEndian(canary):undefined});
    api.log(isCanary?'Canary 校验通过，saved rbp 已跳过。':'padding 精确抵达返回地址。','success');
    api.log(`ret → ${formatHex(address)}，进入 win()。`,'success');
    api.pass(level.explanation);
  };
  host.querySelector('#resetBtn').onclick=()=>{host.querySelector('.memory-grid').outerHTML=stackRows(level);host.querySelector('#bytePreview').classList.add('hidden');api.clear();};
}

function mountChain(level, host, api) {
  let chain=[];
  host.innerHTML=`${question(level)}<div class="panel-title">EXPLOIT CHAIN <span>点击卡片添加</span></div><div class="chain-slots" id="chainSlots"><span style="color:var(--muted);font-size:11px">尚未放置操作</span></div><div class="gadget-list">${level.available.map((g,i)=>`<button class="gadget" data-i="${i}">${escapeHtml(g)}</button>`).join('')}</div>${level.registers?`<div class="registers"><div class="register">RIP<b id="regRip">vuln:ret</b></div><div class="register">RSP<b id="regRsp">stack + 0x28</b></div><div class="register">RDI<b id="regRdi">0x0</b></div><div class="register">RAX<b id="regRax">0x0</b></div></div>`:''}${level.heapDemo?heapView():''}<div class="controls"><button class="primary" id="runBtn">模拟执行</button><button class="secondary" id="undoBtn">撤销一步</button><button class="secondary" id="resetBtn">清空链条</button></div>`;
  const render=()=>{host.querySelector('#chainSlots').innerHTML=chain.length?chain.map((g,i)=>`<span class="chain-item">${i+1}. ${escapeHtml(g)}</span>`).join(''):'<span style="color:var(--muted);font-size:11px">尚未放置操作</span>';};
  host.querySelectorAll('.gadget').forEach(btn=>btn.onclick=()=>{if(chain.length<10){chain.push(level.available[Number(btn.dataset.i)]);render();}});
  host.querySelector('#undoBtn').onclick=()=>{chain.pop();render();api.clear();};
  host.querySelector('#resetBtn').onclick=()=>{chain=[];render();api.clear();};
  host.querySelector('#runBtn').onclick=()=>{
    api.clear();
    if (!chain.length) { api.fail('利用链为空。'); return; }
    const expected=level.correct;
    for(let i=0;i<Math.max(chain.length,expected.length);i++){
      if(chain[i]!==expected[i]){
        const reason=i>=chain.length?`链条在第 ${i+1} 步提前结束，还需要完成后续状态转移。`:i>=expected.length?`第 ${i+1} 步“${chain[i]}”是多余操作，可能破坏已建立的状态。`:`第 ${i+1} 步应为“${expected[i]}”，当前“${chain[i]}”无法得到目标状态。`;
        api.log(reason,'error');api.fail(reason);return;
      }
      traceStep(level,chain[i],i,api,host);
    }
    api.pass(level.explanation);
  };
}
function traceStep(level,step,i,api,host){
  api.log(`[${i+1}] ${step}`,i===level.correct.length-1?'success':'info');
  if(level.registers){
    if(step==='pop rdi; ret') host.querySelector('#regRdi').textContent='waiting: next stack item';
    else if(step==='"/bin/sh"') host.querySelector('#regRdi').textContent='→ "/bin/sh"';
    else if(step==='0') host.querySelector('#regRdi').textContent='0x0';
    else if(step==='prepare_kernel_cred') host.querySelector('#regRax').textContent='root_cred *';
    else if(step==='mov rdi, rax; ret') host.querySelector('#regRdi').textContent='root_cred *';
    host.querySelector('#regRip').textContent=step;
  }
}
function heapView(){return `<div class="heap-layout"><div><div class="panel-title">CHUNKS</div><div class="chunk"><strong>A</strong> @ 0x555000<br>status: allocated</div><div class="chunk"><strong>B</strong> @ 0x5552a0<br>status: allocated</div></div><div><div class="panel-title">TCACHE HEAD</div><div class="bin" id="heapBin">NULL</div></div></div>`;}

function mountFormat(level,host,api){
  const params=level.mode==='leak'?['0x1','0x2','0x3','0x4','0x5','0x636f6465726f705f']:level.mode==='read'?['0x1','0x2','0x3','0x4','0x5','0x6','0x404080']:['0x1','0x2','0x3','0x4','0x5','0x6','0x7','&door_lock'];
  host.innerHTML=`${question(level)}<div class="field"><label>printf 输入 <span>模拟参数表已加载</span></label><input class="text-input" id="fmtInput" autocomplete="off" spellcheck="false" placeholder="%6$p"></div><div class="registers">${params.map((p,i)=>`<div class="register">arg${i+1}<b>${p}</b></div>`).join('')}</div><div class="controls"><button class="primary" id="runBtn">调用 printf</button><button class="secondary" id="resetBtn">清空</button></div><div id="fmtOutput" class="console" style="margin-top:12px;min-height:60px">waiting for printf...</div>`;
  host.querySelector('#runBtn').onclick=()=>{
    const value=host.querySelector('#fmtInput').value.replace(/\s/g,'');
    const output=host.querySelector('#fmtOutput');
    if(!value){api.fail('请输入格式化字符串。');return;}
    let result='';
    if(level.mode==='leak'){
      const m=value.match(/^%([1-6])\$p$/); result=m?params[Number(m[1])-1]:'无法解析：本关只模拟一个位置参数 %N$p';
      output.textContent=result;
      if(value===level.answer)api.pass(level.explanation);else api.fail(value.includes('$s')?'%s 会继续解引用地址，本关只需要参数值本身。':'没有读取到 arg6，请检查位置参数编号和说明符。');
    }else if(level.mode==='read'){
      const m=value.match(/^%([1-7])\$([ps])$/); result=m?(m[2]==='s'?(m[1]==='7'?'FLAG{fmt_read}':'SIGSEGV: invalid string pointer'):params[Number(m[1])-1]):'无法解析：本关模拟 %N$p 或 %N$s';
      output.textContent=result;
      if(value===level.answer)api.pass(level.explanation);else api.fail(result.startsWith('SIGSEGV')?result:'输出不是目标字符串，注意 p 与 s 的解引用差异。');
    }else{
      const m=value.match(/^(?:%(\d+)c)?%8\$n$/);const count=m?Number(m[1]||0):NaN;
      output.textContent=Number.isFinite(count)?`${'A'.repeat(Math.min(count,48))}${count>48?'...':''}\n[write] door_lock = ${count}`:'无法解析：使用 %<宽度>c%8$n';
      if(value===level.answer)api.pass(level.explanation);else api.fail(Number.isFinite(count)?`door_lock 被写为 ${count}，任务要求精确写为 16。`:'写入目标必须是第 8 个参数，并在写入前控制输出计数。');
    }
  };
  host.querySelector('#resetBtn').onclick=()=>{host.querySelector('#fmtInput').value='';host.querySelector('#fmtOutput').textContent='waiting for printf...';api.clear();};
}

function mountCred(level,host,api){
  host.innerHTML=`${question(level)}<div class="ring-diagram"><span class="ring">Ring 3 / uid=1000</span><span>ioctl →</span><span class="ring kernel">Ring 0 / cred</span></div><div class="field"><label>cred.uid <span>当前 1000</span></label><input id="uidInput" inputmode="numeric" value="1000"></div><div class="field"><label>cred.euid <span>当前 1000</span></label><input id="euidInput" inputmode="numeric" value="1000"></div><div class="controls"><button class="primary" id="runBtn">触发越界写</button><button class="secondary" id="resetBtn">恢复凭证</button></div>`;
  host.querySelector('#runBtn').onclick=()=>{
    const uid=host.querySelector('#uidInput').value,euid=host.querySelector('#euidInput').value;
    api.log(`copy_from_user → uid=${uid}, euid=${euid}`);
    if(uid==='0'&&euid==='0'){api.log('commit cred → 当前进程 uid=0 (root)','success');api.pass(level.explanation);}else api.fail('写操作已发生，但当前凭证仍不满足 root 权限要求。');
  };
  host.querySelector('#resetBtn').onclick=()=>{host.querySelector('#uidInput').value='1000';host.querySelector('#euidInput').value='1000';api.clear();};
}
