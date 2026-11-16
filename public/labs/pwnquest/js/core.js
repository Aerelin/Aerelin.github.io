const STORAGE_KEY = 'pwnquest-progress-v1';

export const store = {
  data: load(),
  complete(levelId) {
    this.data.completed[levelId] = { at: new Date().toISOString() };
    this.data.mistakes = this.data.mistakes.filter(m => m.levelId !== levelId);
    save(this.data);
  },
  mistake(levelId, title, reason) {
    this.data.mistakes = this.data.mistakes.filter(m => m.levelId !== levelId);
    this.data.mistakes.unshift({ levelId, title, reason, at: new Date().toISOString() });
    this.data.mistakes = this.data.mistakes.slice(0, 50);
    save(this.data);
  },
  hint(levelId) {
    this.data.hints[levelId] = (this.data.hints[levelId] || 0) + 1;
    save(this.data);
  },
  reset() {
    this.data = { completed: {}, mistakes: [], hints: {} };
    save(this.data);
  }
};

function load() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return { completed: {}, mistakes: [], hints: {}, ...value };
  } catch {
    return { completed: {}, mistakes: [], hints: {} };
  }
}
function save(data) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)); } catch { /* 隐私模式下仍可在本次会话使用 */ }
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}
export function formatHex(value, bytes = 8) {
  return '0x' + BigInt(value).toString(16).padStart(bytes * 2, '0');
}
export function littleEndian(value, bytes = 8) {
  let n = BigInt(value);
  const output = [];
  for (let i = 0; i < bytes; i++) { output.push(Number(n & 255n).toString(16).padStart(2, '0')); n >>= 8n; }
  return output.join(' ');
}
export function parseHex(value) {
  const clean = String(value).trim().replaceAll('_', '');
  if (!/^0x[0-9a-f]+$/i.test(clean) && !/^[0-9a-f]+$/i.test(clean)) throw new Error('请输入十六进制数值，例如 0x401256');
  return BigInt(clean.startsWith('0x') || clean.startsWith('0X') ? clean : '0x' + clean);
}
export function toast(message) {
  const el = document.querySelector('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 2400);
}
export function download(name, content, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// 真实靶场统一接口：Web 版只声明契约，后续由本地 FastAPI 服务实现。
export class RealLabAdapter {
  constructor(endpoint = 'http://127.0.0.1:8000') { this.endpoint = endpoint; }
  async status() {
    try {
      const response = await fetch(`${this.endpoint}/api/health`, { signal: AbortSignal.timeout(1200) });
      return response.ok ? await response.json() : { online: false };
    } catch { return { online: false, message: '未检测到本地实战后端' }; }
  }
  async inspect(path) {
    const response = await fetch(`${this.endpoint}/api/inspect`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ path }) });
    if (!response.ok) throw new Error('ELF 分析失败');
    return response.json();
  }
}
