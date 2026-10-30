(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.WorkbenchUI = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root) {
  'use strict';
  // Presentation only: these helpers never authorize or submit an operation.
  const views = ['task', 'approvals', 'tools', 'records'];
  const tabs = ['plan', 'conclusion', 'analysis', 'evidence'];
  const toolLabels = Object.freeze({read_log:'查看日志',check_disk:'查看磁盘',
    get_service_status:'查看服务状态',restart_service:'模拟重启服务',update_config:'模拟修改配置'});
  const viewLabels = {
    task:['任务工作台','按实际执行证据推进任务，随时核对下一步。'],
    approvals:['审批中心','独立核对申请内容，再处理待审批操作。'],
    tools:['工具调试','生成候选、检查权限，并核对执行结果。'],
    records:['活动记录','查看历史审批、操作记录和原始数据。']
  };
  let doc = null;
  let currentView = 'task';
  let sessionApplied = false;
  let initialHashView = false;
  let viewChosen = false;

  function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
  function array(value) { return Array.isArray(value) ? value : []; }
  function text(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'object') {
      try { return JSON.stringify(value, null, 2); } catch (_) { return '无法显示该数据'; }
    }
    return String(value);
  }
  function escapeHTML(value) {
    return text(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  }
  function el(id) { return doc && typeof doc.getElementById === 'function' ? doc.getElementById(id) : null; }
  function setText(id, value) { const node = el(id); if (node) node.textContent = text(value); }
  function setHTML(id, value) { const node = el(id); if (node) node.innerHTML = value; }
  function setHidden(id, hidden) { const node = el(id); if (node) node.hidden = hidden; }
  function attr(node, key, value) { if (node && typeof node.setAttribute === 'function') node.setAttribute(key, String(value)); }
  function selectData(attribute, keys) {
    if (!doc || typeof doc.querySelectorAll !== 'function') return [];
    return Array.from(doc.querySelectorAll(attribute === 'view' ? '[data-view]' : '[data-task-tab]'))
      .filter(node => node && node.dataset && keys.includes(node.dataset[attribute]));
  }
  function tool(value) {
    return Object.prototype.hasOwnProperty.call(toolLabels, value) ? toolLabels[value] : text(value) || '未提供工具';
  }
  function empty(message) { return '<p class="empty-state">' + escapeHTML(message) + '</p>'; }
  function chip(value) { return '<span class="resource-chip">' + escapeHTML(value) + '</span>'; }
  function ownLabel(labels, key, fallback) {
    return Object.prototype.hasOwnProperty.call(labels, key) ? labels[key] : fallback;
  }

  function paintView(key) {
    currentView = key;
    for (const item of views) setHidden('view-' + item, item !== key);
    const content = el('workspaceContent');
    if (content && content.dataset) content.dataset.view = key;
    setHidden('operationRail', !['task', 'tools'].includes(key));
    for (const node of selectData('view', views)) {
      // workspaceContent has data-view too, but is a container, never a nav link.
      if (node.id === 'workspaceContent') continue;
      const active = node.dataset.view === key;
      if (active) attr(node, 'aria-current', 'page');
      else if (typeof node.removeAttribute === 'function') node.removeAttribute('aria-current');
      else attr(node, 'aria-current', 'false');
      if (node.dataset) node.dataset.active = String(active);
    }
    setText('viewTitle', viewLabels[key][0]);
    setText('viewSubtitle', viewLabels[key][1]);
  }
  function showView(key) {
    if (!views.includes(key)) return false;
    viewChosen = true;
    paintView(key);
    if (root && typeof root.scrollTo === 'function') root.scrollTo({top:0,behavior:'instant'});
    if (root && root.location) {
      if (root.history && typeof root.history.replaceState === 'function') {
        try { root.history.replaceState(null, '', '#' + key); }
        catch (_) { root.location.hash = '#' + key; }
      } else root.location.hash = '#' + key;
    }
    return true;
  }
  function showTaskTab(key) {
    if (!tabs.includes(key)) return false;
    for (const item of tabs) {
      setHidden('task-panel-' + item, item !== key);
      attr(el('task-panel-' + item), 'role', 'tabpanel');
    }
    for (const node of selectData('taskTab', tabs)) {
      attr(node, 'role', 'tab');
      attr(node, 'aria-controls', 'task-panel-' + node.dataset.taskTab);
      attr(node, 'aria-selected', node.dataset.taskTab === key);
      attr(node, 'tabindex', node.dataset.taskTab === key ? '0' : '-1');
      if (node.id) attr(el('task-panel-' + node.dataset.taskTab), 'aria-labelledby', node.id);
    }
    return true;
  }
  function init(document) {
    doc = document || null;
    sessionApplied = false;
    viewChosen = false;
    const hash = root && root.location ? text(root.location.hash).replace(/^#(?:view=)?/, '') : '';
    initialHashView = views.includes(hash);
    paintView(initialHashView ? hash : 'task');
    showTaskTab('plan');
    for (const node of selectData('view', views)) {
      if (node.id === 'workspaceContent' || typeof node.addEventListener !== 'function' || node.__workbenchNav) continue;
      node.__workbenchNav = true;
      node.addEventListener('click', event => {
        if (event && typeof event.preventDefault === 'function') event.preventDefault();
        showView(node.dataset.view);
      });
    }
    for (const node of selectData('taskTab', tabs)) {
      if (typeof node.addEventListener !== 'function' || node.__workbenchTab) continue;
      node.__workbenchTab = true;
      node.addEventListener('click', () => showTaskTab(node.dataset.taskTab));
      node.addEventListener('keydown', event => {
        if (!event || !['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
        const index = tabs.indexOf(node.dataset.taskTab);
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
          : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
        if (typeof event.preventDefault === 'function') event.preventDefault();
        showTaskTab(tabs[next]);
        const button = selectData('taskTab', tabs).find(item => item.dataset.taskTab === tabs[next]);
        if (button && typeof button.focus === 'function') button.focus();
      });
    }
    return api;
  }
  function applySession(data) {
    data = object(data);
    if (!data.authenticated) { sessionApplied = false; return; }
    if (!sessionApplied) {
      if (!initialHashView && !viewChosen) paintView(data.role === 'approver' ? 'approvals' : 'task');
      sessionApplied = true;
    }
  }

  function timelineItem(state, label, title, description, observedAt) {
    const observedDate = observedAt ? new Date(typeof observedAt === 'number' ? observedAt * 1000 : observedAt) : null;
    const observedTime = observedDate && !Number.isNaN(observedDate.getTime())
      ? '<time class="step-time" datetime="' + escapeHTML(observedDate.toISOString()) + '" title="' + escapeHTML(observedDate.toLocaleString('zh-CN', {hour12:false})) + '">'
        + escapeHTML(observedDate.toLocaleTimeString('zh-CN', {hour12:false})) + '</time>' : '';
    return '<li class="timeline-item" data-state="' + state + '"><span class="timeline-status">' + escapeHTML(label)
      + '</span><div class="step-content"><h3 class="timeline-title">' + escapeHTML(title) + '</h3>'
      + (description ? '<p class="timeline-description">' + escapeHTML(description) + '</p>' : '') + '</div>' + observedTime + '</li>';
  }
  function successfulObservation(item) {
    return item && typeof item === 'object' && item.executed !== false && !item.error
      && !['failed','blocked','denied','stopped','limit','submitted'].includes(item.status);
  }
  function assessmentText(value, observations) {
    let valueText = text(value);
    // Reference identifiers remain available with the original evidence below.
    for (const item of observations) {
      const prefix = '[' + text(item.operation_id) + ']';
      if (item.operation_id && valueText.startsWith(prefix)) valueText = valueText.slice(prefix.length).trimStart();
    }
    return valueText.replace(/^\[(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]\s*/i, '');
  }
  function renderAssessment(id, values, fallback, observations) {
    const items = array(values);
    setHTML(id, items.length ? items.map(value => '<div class="assessment-card">' + escapeHTML(assessmentText(value, observations)) + '</div>').join('') : empty(fallback));
  }
  function renderTask(result) {
    result = object(result);
    const plan = array(result.plan);
    const observations = array(result.observations).filter(item => item && typeof item === 'object');
    const executed = observations.filter(successfulObservation);
    const scope = object(result.scope);
    const status = text(result.task_status);
    const runner = text(result.runner_state);
    const stopped = ['blocked','limit','stopped','unsupported'].includes(status) || ['blocked','limit','stopped','stopping'].includes(runner);
    const waiting = runner === 'waiting_approval';
    attr(el('taskWorkspace'),'data-task-status',status);
    setText('planCount', plan.length);
    setText('completedCount', executed.length);
    const rows = executed.map(item => timelineItem('executed', '已执行', tool(item.tool)
      + (item.target ? ' · ' + text(item.target) : ''), item.observed_at ? '' : '采集时间未提供', item.observed_at));
    if (stopped) rows.push(timelineItem('blocked', '已暂停', ownLabel({blocked:'任务受阻',limit:'达到执行上限',stopped:'任务已停止',unsupported:'当前能力暂不支持'}, status, '任务已停止'), '请核对下方原因与下一步提示。'));
    else if (waiting) rows.push(timelineItem('current', '等待审批', result.tool ? tool(result.tool) : '待独立账号审批', '尚未确认执行；审批通过后由原任务流程继续。'));
    else if (runner === 'running') {
      const stage = ownLabel({executing:'正在执行下一步',authorizing:'正在检查执行权限',planning:'正在根据证据分析'}, result.phase, '任务正在处理');
      rows.push(timelineItem('current', '当前', stage, result.tool ? tool(result.tool) : '等待后端返回下一步状态。'));
    } else if (status === 'propose' && result.tool && (executed.length || !plan.length)) rows.push(timelineItem('current', '待执行', tool(result.tool), '已生成下一步候选，尚未确认执行。'));
    else if (status === 'observed') rows.push(timelineItem('current', '待分析', '本步已执行，等待继续分析', '下一步将依据已采集证据确定。'));
    if (!executed.length && !stopped && !waiting && runner !== 'running')
      for (const item of plan) rows.push(timelineItem('planned', '计划', text(item), ''));
    const remaining = array(result.remaining_requirements);
    setHTML('planTimeline', rows.length ? rows.join('') : empty('尚未生成计划，也没有实际执行记录。'));
    const chips = [
      ...array(scope.services).map(value => chip('服务：' + text(value))),
      ...array(scope.forbidden_tools).map(value => chip('禁止：' + tool(value)))
    ];
    setHTML('taskResourceChips', chips.join(''));
    setHTML('taskResourceDefaults', array(scope.defaults).map(value => chip(value)).join(''));
    let next = '请创建任务，或等待后端返回当前任务状态。';
    if (stopped) next = '先核对停止原因与执行证据；需要继续时，请调整任务后重新创建。';
    else if (waiting) next = '等待另一位有权限的用户审批；可在审批中心查看申请。';
    else if (status === 'clarify') next = '请在任务输入区补充所需信息，再继续规划。';
    else if (runner === 'running') next = '任务正在处理；可查看实时证据或请求停止。';
    else if (status === 'propose') next = result.autonomy === 'read_only' ? '核对计划后，点击“启动自主执行”。' : '核对下一步候选，完成权限检查和所需审批后执行。';
    else if (status === 'observed') next = '点击“继续分析”，根据已执行结果确定下一步。';
    else if (status === 'complete') next = '查看诊断结论、完整分析与执行证据，核对结果及局限。';
    if (remaining.length) next += '\n尚需：' + remaining.map(value => {
      const item=object(value);
      return tool(item.tool)+(item.target ? '（'+text(item.target)+'）' : '')+(item.reason ? ' · '+text(item.reason) : '');
    }).join('；');
    setText('taskNextAction', next);
    const alertParts = [];
    if (stopped || status === 'clarify') alertParts.push(text(result.message) || next);
    if (waiting) alertParts.push('任务已暂停：等待独立账号审批，尚未执行待审批操作。');
    if (result.diagnostic) alertParts.push(text(result.diagnostic));
    if (observations.some(item => item.truncated)) alertParts.push('部分证据已截断，结论仅依据已采集片段。');
    setText('taskAlert', alertParts.join('\n'));
    setHidden('taskAlert', !alertParts.length);
    const alertNode = el('taskAlert');
    if (alertNode && alertNode.dataset) alertNode.dataset.kind = stopped ? 'error' : 'warning';
    const assessment = object(result.diagnostic_assessment);
    renderAssessment('conclusionFacts', assessment.confirmed, '尚无已采集事实。', observations);
    renderAssessment('conclusionHypotheses', assessment.hypotheses, '暂无可支持的原因线索。', observations);
    renderAssessment('conclusionUnknowns', assessment.unknowns, '尚未提供局限说明，请结合实际证据核对。', observations);
    const paragraphs = text(result.message).split(/\r?\n/).filter(value => value.trim());
    const sentences = paragraphs.flatMap(value => value.match(/[^。！？]+[。！？]*|[。！？]+/g) || [value]);
    setHTML('taskNarrative', sentences.length ? sentences.map(value => '<li class="narrative-item">' + escapeHTML(value) + '</li>').join('') : empty('暂无模型分析说明。'));
    setHTML('evidenceRows', observations.length ? observations.map((item, index) => '<article class="evidence-card"><h3>'
      + escapeHTML((index + 1) + '. ' + tool(item.tool)) + '</h3><dl class="evidence-meta"><dt>目标</dt><dd>'
      + escapeHTML(item.target || '未提供') + '</dd><dt>来源</dt><dd>' + escapeHTML(item.source || '未提供')
      + '</dd><dt>时间</dt><dd>' + escapeHTML(item.observed_at || '未提供') + '</dd></dl>'
      + (item.truncated ? '<p class="evidence-warning">本条结果已截断。</p>' : '')
      + '<h4>原始片段</h4><pre>' + escapeHTML(item.result_excerpt || '未提供原始片段')
      + '</pre></article>').join('') : empty('暂无执行证据，尚不能据此确认任务结果。'));
    setText('taskEvidenceData',observations.length ? text(observations) : '暂无执行证据。');
  }
  function resetTask() { renderTask({}); showTaskTab('plan'); }
  function setBackend(status) {
    status = object(status);
    const resources = object(status.execution_resources);
    const backend = ownLabel({local_readonly:'真实只读',sandbox:'本地模拟'}, status.execution_backend, '执行模式未知');
    const chips = [chip('模式：' + backend), ...array(resources.services).map(value => chip('服务：' + text(value))),
      ...array(resources.log_paths).map(value => chip('日志：' + text(value)))];
    if (!array(resources.services).length) chips.push(chip('服务未配置'));
    if (!array(resources.log_paths).length) chips.push(chip('日志未配置'));
    setHTML('backendResources', chips.join(''));
  }
  function approvalMarkup(value) {
    const item = object(value);
    const args = object(item.arguments);
    const parameters = Object.entries(args).map(([key, value]) => '<dt>' + escapeHTML(ownLabel({name:'服务',path:'路径',lines:'读取行数',content:'配置全文'}, key, key))
      + '</dt><dd>' + (key === 'content' || typeof value === 'object' ? '<pre>' + escapeHTML(value) + '</pre>' : escapeHTML(value)) + '</dd>').join('');
    return '<h3>' + escapeHTML(tool(item.tool)) + '</h3><dl class="approval-meta">' + parameters
      + '<dt>申请人</dt><dd>' + escapeHTML(item.requester || '未提供') + '</dd><dt>原因</dt><dd>'
      + escapeHTML(item.reason || '未提供') + '</dd></dl><p class="record-reference">申请编号：' + escapeHTML(item.request_id || '未提供') + '</p>';
  }
  function renderRecords(status) {
    status = object(status);
    const approvals = array(status.approvals), operations = array(status.operations);
    const auditCount = object(status.audit).count;
    setHTML('recordsMetrics', [['审批', approvals.length], ['操作', operations.length], ['审计', auditCount === undefined ? '未知' : auditCount]]
      .map(([label, value]) => '<div class="metric-item"><span>' + label + '</span><strong>' + escapeHTML(value) + '</strong></div>').join(''));
    const statusNames = {pending:'待审批',approved:'已审批',consumed:'审批已使用',expired:'已过期',rejected:'已拒绝',completed:'已完成',executed:'已执行',failed:'失败',rolled_back:'已恢复',submitted:'已提交',success:'已完成'};
    const record = (value, type) => {
      const item = object(value);
      const target = item.target || object(item.arguments).name || object(item.arguments).path;
      const timestamp = item.created_at || item.timestamp;
      const date = timestamp ? new Date(typeof timestamp === 'number' ? timestamp * 1000 : timestamp) : null;
      const displayTime = date && !Number.isNaN(date.getTime()) ? date.toLocaleString('zh-CN', {hour12:false}) : text(timestamp);
      return '<article class="record-row"><h3>' + type + ' · ' + escapeHTML(tool(item.tool)) + '</h3><p>'
        + escapeHTML(ownLabel(statusNames, item.status, item.status || '状态未知'))
        + (target ? ' · ' + escapeHTML(target) : '') + (item.requester ? ' · 申请人：' + escapeHTML(item.requester) : '')
        + '</p><p class="record-reference">' + escapeHTML(item.request_id || item.operation_id || '未提供编号')
        + (timestamp ? ' · ' + escapeHTML(displayTime) : '') + '</p></article>';
    };
    setHTML('recordsRows', approvals.map(item => record(item, '审批')).concat(operations.map(item => record(item, '操作'))).join('') || empty('暂无审批或操作记录。'));
  }
  const api = {init,applySession,renderTask,resetTask,setBackend,renderRecords,showView,showTaskTab,approvalMarkup,escapeHTML};
  return api;
});
