// PwnDaily - 每日 Pwn 练习应用
const STORAGE_KEY = 'pwndaily_records_v1';
const QUIZZES_DIR = 'quizzes';

// ---------- Utilities ----------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const fmtDate = (d = new Date()) => {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
};
const toast = (msg) => {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 2200);
};
const normalize = (s) => String(s ?? '').trim().toLowerCase().replace(/\s+/g, ' ');

// ---------- Storage ----------
function loadRecords() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
  } catch { return {}; }
}
function saveRecords(records) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
}

// ---------- Data loading ----------
async function fetchJson(url) {
  const r = await fetch(url, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function loadQuizIndex() {
  try {
    const idx = await fetchJson(`${QUIZZES_DIR}/index.json`);
    return Array.isArray(idx) ? idx : (idx.dates || []);
  } catch {
    return [];
  }
}

async function loadQuiz(date) {
  return fetchJson(`${QUIZZES_DIR}/${date}.json`);
}

async function loadTodayQuiz() {
  const today = fmtDate();
  try {
    const q = await loadQuiz(today);
    return { quiz: q, date: today };
  } catch {
    // fall back to latest from index
    const index = await loadQuizIndex();
    if (index.length === 0) return { quiz: null, date: today };
    const latest = index[index.length - 1];
    try {
      const q = await loadQuiz(latest);
      return { quiz: q, date: latest, isLatest: true };
    } catch {
      return { quiz: null, date: today };
    }
  }
}

// ---------- Grading ----------
function gradeChoice(q, userAns) {
  return Number(userAns) === q.answer;
}
function gradeFill(q, userAns) {
  const correct = Array.isArray(q.answer) ? q.answer : [q.answer];
  const u = normalize(userAns);
  return correct.some(a => normalize(a) === u);
}
function gradeQA(q, userAns, selfChecked) {
  return !!selfChecked;
}

// ---------- Rendering ----------
let state = {
  view: 'today',
  quiz: null,
  quizDate: null,
  answers: {},    // { qid: userAnswer }
  qaSelfCheck: {}, // { qid: bool }
  submitted: false,
  record: null,
};

function render() {
  const app = $('#app');
  if (state.view === 'today') {
    renderToday(app);
  } else {
    renderHistory(app);
  }
  // sync tab active state
  $$('.icon-button').forEach(b => b.classList.remove('active'));
  $(state.view === 'today' ? '#todayTab' : '#historyTab').classList.add('active');
}

function renderToday(app) {
  if (!state.quiz) {
    app.innerHTML = `
      <div class="empty-state">
        <h3>今日试卷尚未生成</h3>
        <p>每天 22:01 会自动生成一份新的 Pwn 练习卷。<br>请稍后刷新页面，或前往「历史记录」查看往期试卷。</p>
      </div>`;
    return;
  }

  const quiz = state.quiz;
  const rec = state.record;
  const submitted = state.submitted || (rec && rec.completed);

  let html = `
    <section class="hero">
      <div class="eyebrow">PWN DAILY PRACTICE</div>
      <h1><span>${quiz.title || 'Pwn 每日一练'}</span></h1>
      <p>涵盖选择、填空、问答多种题型，按难度梯度排列。建议独立作答后查看答案与讲解。</p>
      <div class="hero-meta">
        <div class="meta-chip"><b>${quiz.questions.length}</b> 题</div>
        <div class="meta-chip"><b>${quiz.estimatedMinutes || 30}</b> 分钟</div>
        <div class="meta-chip">日期 <b>${state.quizDate}</b></div>
      </div>
    </section>

    <div class="quiz-header">
      <h2>本次知识点</h2>
      <div class="quiz-topics">
        ${(quiz.topics || []).map(t => `<span class="topic-tag">${t}</span>`).join('')}
      </div>
      ${submitted ? '' : `<div class="quiz-timer"><span>⏱ 建议用时</span><div class="timer-bar"><div class="timer-fill" id="timerFill"></div></div><span id="timerText">00:00</span></div>`}
    </div>
  `;

  quiz.questions.forEach((q, i) => {
    const num = i + 1;
    html += renderQuestion(q, num, submitted);
  });

  // submit bar or result
  if (!submitted) {
    const answered = Object.keys(state.answers).filter(k => state.answers[k] !== '' && state.answers[k] != null).length;
    html += `
      <div class="submit-bar">
        <div class="submit-info">已作答 <b style="color:var(--cyan)">${answered}</b> / ${quiz.questions.length} 题</div>
        <button class="primary" id="submitBtn">提交并查看答案</button>
      </div>`;
  } else {
    const result = computeResult();
    html += renderResultBanner(result);
  }

  app.innerHTML = html;
  bindQuestionEvents();
  if (!submitted) startTimer();
  if (!submitted) $('#submitBtn').addEventListener('click', submitQuiz);
}

function diffLabel(d) {
  return { basic: '基础', medium: '中等', hard: '高难' }[d] || d;
}
function typeLabel(t) {
  return { choice: '选择', fill: '填空', qa: '问答' }[t] || t;
}

function renderQuestion(q, num, submitted) {
  const userAns = state.answers[q.id];
  let body = '';

  if (q.type === 'choice') {
    const opts = q.options.map((opt, i) => {
      let cls = 'option-button';
      if (submitted) {
        if (i === q.answer) cls += ' correct';
        else if (Number(userAns) === i) cls += ' wrong';
      } else if (Number(userAns) === i) {
        cls += ' selected';
      }
      const letter = String.fromCharCode(65 + i);
      return `<button class="${cls}" data-qid="${q.id}" data-idx="${i}" ${submitted ? 'disabled' : ''}>
        <span class="opt-label">${letter}.</span><span>${opt}</span>
      </button>`;
    }).join('');
    body = `<div class="option-list">${opts}</div>`;
  } else if (q.type === 'fill') {
    const cls = 'fill-input' + (submitted ? (gradeFill(q, userAns) ? ' correct' : ' wrong') : '');
    body = `<input class="${cls}" data-qid="${q.id}" type="text" placeholder="输入答案…" value="${userAns != null ? String(userAns).replace(/"/g, '&quot;') : ''}" ${submitted ? 'disabled' : ''}>`;
  } else if (q.type === 'qa') {
    const checked = state.qaSelfCheck[q.id] ? 'checked' : '';
    body = `
      <textarea class="qa-textarea" data-qid="${q.id}" placeholder="在此作答，可写 exp 片段、命令或思路…" ${submitted ? 'disabled' : ''}>${userAns || ''}</textarea>
      <label class="qa-selfcheck"><input type="checkbox" data-qid="${q.id}" data-selfcheck ${submitted ? 'disabled' : ''} ${checked}> 我已对照参考答案，本题作答正确</label>
    `;
  }

  let answerReveal = '';
  if (submitted) {
    answerReveal = `
      <div class="answer-block">
        <div class="answer-label">参考答案</div>
        <div class="answer-content">${formatAnswer(q)}</div>
        ${q.explanation ? `<div class="explain"><strong>讲 解</strong>${q.explanation}</div>` : ''}
      </div>`;
  }

  return `
    <section class="q-card" id="q-${q.id}">
      <div class="q-head">
        <span class="q-num">Q${String(num).padStart(2, '0')}</span>
        <div class="q-meta">
          <span class="diff ${q.difficulty}">${diffLabel(q.difficulty)}</span>
          <span class="q-type">${typeLabel(q.type)}</span>
          <span class="q-type">${q.topic || ''}</span>
        </div>
      </div>
      <div class="q-body">
        <p class="q-text">${q.question}</p>
        ${body}
        ${answerReveal}
      </div>
    </section>`;
}

function formatAnswer(q) {
  if (q.type === 'choice') {
    const letter = String.fromCharCode(65 + q.answer);
    return `${letter}. ${q.options[q.answer]}`;
  }
  if (q.type === 'fill') {
    return Array.isArray(q.answer) ? q.answer.join(' 或 ') : q.answer;
  }
  return q.answer;
}

function bindQuestionEvents() {
  $$('.option-button').forEach(btn => {
    btn.addEventListener('click', () => {
      if (state.submitted) return;
      const qid = btn.dataset.qid;
      const idx = btn.dataset.idx;
      state.answers[qid] = idx;
      // update UI
      $$(`.option-button[data-qid="${qid}"]`).forEach(b => b.classList.remove('selected'));
      btn.classList.add('selected');
      updateSubmitInfo();
    });
  });
  $$('.fill-input').forEach(inp => {
    inp.addEventListener('input', () => { state.answers[inp.dataset.qid] = inp.value; updateSubmitInfo(); });
  });
  $$('.qa-textarea').forEach(ta => {
    ta.addEventListener('input', () => { state.answers[ta.dataset.qid] = ta.value; });
  });
  $$('[data-selfcheck]').forEach(cb => {
    cb.addEventListener('change', () => { state.qaSelfCheck[cb.dataset.qid] = cb.checked; });
  });
}

function updateSubmitInfo() {
  const info = $('.submit-info');
  if (!info) return;
  const total = state.quiz.questions.length;
  const answered = Object.keys(state.answers).filter(k => {
    const v = state.answers[k];
    return v !== '' && v != null && String(v).trim() !== '';
  }).length;
  info.innerHTML = `已作答 <b style="color:var(--cyan)">${answered}</b> / ${total} 题`;
}

// ---------- Timer ----------
let timerInterval = null;
let timerSeconds = 0;
function startTimer() {
  stopTimer();
  timerSeconds = 0;
  const fill = $('#timerFill');
  const txt = $('#timerText');
  if (!txt) return;
  const total = (state.quiz.estimatedMinutes || 30) * 60;
  timerInterval = setInterval(() => {
    timerSeconds++;
    const m = String(Math.floor(timerSeconds / 60)).padStart(2, '0');
    const s = String(timerSeconds % 60).padStart(2, '0');
    txt.textContent = `${m}:${s}`;
    if (fill) fill.style.width = Math.min(100, (timerSeconds / total) * 100) + '%';
  }, 1000);
}
function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

// ---------- Submit ----------
function computeResult() {
  const quiz = state.quiz;
  let correct = 0;
  const details = quiz.questions.map(q => {
    let ok = false;
    const ua = state.answers[q.id];
    if (q.type === 'choice') ok = gradeChoice(q, ua);
    else if (q.type === 'fill') ok = gradeFill(q, ua);
    else if (q.type === 'qa') ok = gradeQA(q, ua, state.qaSelfCheck[q.id]);
    if (ok) correct++;
    return { id: q.id, correct: ok };
  });
  return { correct, total: quiz.questions.length, details };
}

function submitQuiz() {
  const unanswered = state.quiz.questions.filter(q => {
    const ua = state.answers[q.id];
    return ua === undefined || ua === '' || ua === null || String(ua).trim() === '';
  });
  if (unanswered.length > 0) {
    if (!confirm(`还有 ${unanswered.length} 题未作答，确定提交吗？`)) return;
  }
  stopTimer();
  state.submitted = true;
  const result = computeResult();
  // save record
  const records = loadRecords();
  records[state.quizDate] = {
    date: state.quizDate,
    completed: true,
    answers: { ...state.answers },
    qaSelfCheck: { ...state.qaSelfCheck },
    score: result.correct,
    total: result.total,
    submittedAt: new Date().toISOString(),
    elapsedSeconds: timerSeconds,
  };
  saveRecords(records);
  state.record = records[state.quizDate];
  render();
  window.scrollTo({ top: 0, behavior: 'smooth' });
  toast(`已提交 · 得分 ${result.correct}/${result.total}`);
}

function renderResultBanner(result) {
  const pct = result.correct / result.total;
  const pass = pct >= 0.6;
  const cls = pass ? 'pass' : 'fail';
  const elapsed = state.record?.elapsedSeconds;
  const timeText = elapsed ? ` · 用时 ${Math.floor(elapsed/60)}分${elapsed%60}秒` : '';
  return `
    <div class="result-banner ${cls}">
      <div class="result-score">${result.correct}<small> / ${result.total}</small></div>
      <div class="result-detail">${pass ? '通过，继续保持！' : '未达 60%，建议复习错题后重做。'}${timeText}</div>
    </div>`;
}

// ---------- History ----------
async function renderHistory(app) {
  app.innerHTML = `<div class="loading">加载历史记录…</div>`;
  const index = await loadQuizIndex();
  const records = loadRecords();

  if (index.length === 0) {
    app.innerHTML = `<div class="history-empty">暂无历史试卷</div>`;
    return;
  }

  let html = `
    <section class="hero">
      <div class="eyebrow">HISTORY</div>
      <h1>历史<span>试卷</span></h1>
      <p>共 ${index.length} 份试卷。已完成 ${Object.values(records).filter(r => r.completed).length} 份。</p>
    </section>
    <div class="history-list">
  `;

  // show from newest to oldest
  [...index].reverse().forEach(date => {
    const rec = records[date];
    const done = rec && rec.completed;
    let scoreHtml = `<span class="hist-score">--</span><div class="hist-meta">未作答</div>`;
    if (done) {
      const pct = rec.score / rec.total;
      const cls = pct >= 0.8 ? 'good' : pct >= 0.6 ? 'mid' : 'bad';
      scoreHtml = `<span class="hist-score ${cls}">${rec.score}/${rec.total}</span><div class="hist-meta">${new Date(rec.submittedAt).toLocaleString('zh-CN')}</div>`;
    }
    html += `
      <div class="history-item">
        <div class="hist-left">
          <h3>Pwn 每日一练 · ${date}</h3>
          <p>${done ? '已完成' : '待作答'}</p>
          <div class="hist-tags">
            <span class="topic-tag">${done ? `${rec.score}/${rec.total}` : '未作答'}</span>
          </div>
        </div>
        <div class="hist-right">
          ${scoreHtml}
          <button class="view-btn" data-date="${date}">${done ? '查看作答' : '开始作答'}</button>
        </div>
      </div>`;
  });
  html += `</div>`;
  app.innerHTML = html;

  $$('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => openHistoryQuiz(btn.dataset.date));
  });
}

async function openHistoryQuiz(date) {
  try {
    const quiz = await loadQuiz(date);
    const records = loadRecords();
    const rec = records[date];
    state.quiz = quiz;
    state.quizDate = date;
    state.answers = rec?.answers ? { ...rec.answers } : {};
    state.qaSelfCheck = rec?.qaSelfCheck ? { ...rec.qaSelfCheck } : {};
    state.submitted = !!(rec && rec.completed);
    state.record = rec || null;
    state.view = 'today';
    render();
  } catch (e) {
    toast('加载试卷失败');
  }
}

// ---------- Export / Import ----------
function exportRecords() {
  const records = loadRecords();
  const blob = new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `pwndaily-records-${fmtDate()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('答题记录已导出');
}

function importRecords(file) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (typeof data !== 'object') throw new Error('格式错误');
      const existing = loadRecords();
      Object.assign(existing, data);
      saveRecords(existing);
      toast('记录已导入');
      render();
    } catch {
      toast('导入失败：文件格式错误');
    }
  };
  reader.readAsText(file);
}

// ---------- Init ----------
async function init() {
  $('#todayLabel').textContent = fmtDate();

  $('#todayTab').addEventListener('click', () => { state.view = 'today'; loadAndRenderToday(); });
  $('#historyTab').addEventListener('click', () => { state.view = 'history'; stopTimer(); render(); });
  $('#homeBtn').addEventListener('click', () => { state.view = 'today'; loadAndRenderToday(); });
  $('#exportBtn').addEventListener('click', exportRecords);
  $('#importBtn').addEventListener('click', () => $('#importFile').click());
  $('#importFile').addEventListener('change', (e) => {
    if (e.target.files[0]) importRecords(e.target.files[0]);
    e.target.value = '';
  });

  await loadAndRenderToday();
}

async function loadAndRenderToday() {
  $('#app').innerHTML = `<div class="loading">加载今日试卷…</div>`;
  const { quiz, date } = await loadTodayQuiz();
  state.quiz = quiz;
  state.quizDate = date;
  state.answers = {};
  state.qaSelfCheck = {};
  state.submitted = false;
  state.record = null;
  if (quiz) {
    const records = loadRecords();
    const rec = records[date];
    if (rec && rec.completed) {
      state.answers = { ...rec.answers };
      state.qaSelfCheck = { ...rec.qaSelfCheck };
      state.submitted = true;
      state.record = rec;
    }
  }
  state.view = 'today';
  render();
}

init();
