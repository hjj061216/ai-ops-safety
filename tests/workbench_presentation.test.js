/* Exercises the real presentation module against a small, browser-shaped DOM. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness(hash = '') {
  const nodes = {};
  function node(id, dataset = {}) {
    return nodes[id] = { id, dataset, hidden:false, textContent:'', innerHTML:'', attributes:{}, listeners:{},
      setAttribute(name,value) { this.attributes[name] = String(value); },
      removeAttribute(name) { delete this.attributes[name]; },
      addEventListener(name,handler) { this.listeners[name] = handler; },
      focus() { this.focused = true; } };
  }
  for (const id of ['workspaceContent','operationRail','viewTitle','viewSubtitle','planTimeline','planCount',
    'completedCount','taskResourceChips','taskResourceDefaults','taskNextAction','taskAlert','conclusionFacts','conclusionHypotheses',
    'conclusionUnknowns','taskNarrative','evidenceRows','backendResources','recordsRows','recordsMetrics',
    'taskMessage','taskPlan','taskScope','taskRemaining','taskEvidence','taskEvidenceData','resourceScope','taskModeDescription']) node(id);
  for (const key of ['task','approvals','tools','records']) {
    node('nav-'+key,{view:key}); node('view-'+key);
  }
  for (const key of ['plan','conclusion','analysis','evidence']) {
    node('tab-'+key,{taskTab:key}); node('task-panel-'+key);
  }
  // Returning all nodes deliberately catches selector assumptions in the page VM.
  const document = {getElementById:id=>nodes[id] || null,querySelectorAll:()=>Object.values(nodes)};
  const window = {location:{hash}};
  const context = vm.createContext({window,document,console});
  const filename = path.join(__dirname,'..','web','workbench.js');
  assert.ok(fs.existsSync(filename), 'workbench presentation module must exist');
  vm.runInContext(fs.readFileSync(filename,'utf8'),context);
  const ui = window.WorkbenchUI;
  assert.ok(ui && typeof ui.renderTask === 'function', 'presentation API is available');
  ui.init(document);
  return {ui,nodes,window};
}

const cases = {
  evidence_view_does_not_duplicate_long_fragments_and_raw_data_remains_available() {
    const {ui,nodes:n}=harness();
    ui.renderTask({observations:[{tool:'read_log',result_excerpt:'unique-fragment',call_digest:'original-digest',source:'fixed log',observed_at:123}]});
    assert.equal((n.evidenceRows.innerHTML.match(/unique-fragment/g)||[]).length,1);
    assert.match(n.taskEvidenceData.textContent,/original-digest/);
    assert.match(n.taskEvidenceData.textContent,/unique-fragment/);
  },
  current_candidate_and_remaining_requirement_do_not_duplicate_initial_plan() {
    const {ui,nodes:n}=harness();
    ui.renderTask({task_status:'propose',tool:'get_service_status',arguments:{name:'nginx'},
      plan:['查询 nginx 状态','若异常，查看日志'],remaining_requirements:[{tool:'get_service_status',target:'nginx'}]});
    assert.equal((n.planTimeline.innerHTML.match(/class="timeline-item"/g)||[]).length,2);
    ui.renderTask({task_status:'propose',tool:'read_log',plan:['检查日志并总结'],
      observations:[{tool:'get_service_status',target:'nginx'}],remaining_requirements:[{tool:'read_log',target:'/var/log/nginx/error.log'}]});
    assert.equal((n.planTimeline.innerHTML.match(/class="timeline-item"/g)||[]).length,2);
    assert.match(n.taskNextAction.textContent,/日志/);
  },
  plan_does_not_invent_executed_steps() {
    const {ui,nodes:n} = harness();
    ui.renderTask({task_status:'propose',plan:['检查服务','若异常则读取日志'],steps_completed:5,message:'先进行检查。'});
    assert.equal(n.completedCount.textContent,'0');
    assert.equal(n.planCount.textContent,'2');
    assert.equal((n.planTimeline.innerHTML.match(/data-state="planned"/g)||[]).length,2);
    assert.doesNotMatch(n.planTimeline.innerHTML,/data-state="executed"|%/);
    assert.match(n.planTimeline.innerHTML,/若异常则读取日志/);
  },
  actual_observations_and_new_conditional_steps_form_a_dynamic_timeline() {
    const {ui,nodes:n} = harness();
    ui.renderTask({task_status:'propose',runner_state:'running',phase:'authorizing',tool:'read_log',arguments:{path:'/a.log'},
      plan:['若健康异常，检查日志','若日志指向空间不足，再检查磁盘'],
      remaining_requirements:[{tool:'check_disk',target:'',reason:'日志出现空间不足线索'}],
      observations:[{tool:'get_service_status',target:'nginx',result_excerpt:'HTTP 503',source:'health',observed_at:123}]});
    assert.equal(n.completedCount.textContent,'1');
    assert.equal((n.planTimeline.innerHTML.match(/data-state="executed"/g)||[]).length,1);
    assert.match(n.planTimeline.innerHTML,/检查执行权限/);
    assert.match(n.taskNextAction.textContent,/空间不足/);
    assert.match(n.evidenceRows.innerHTML,/HTTP 503/);
    assert.match(n.evidenceRows.innerHTML,/health/);
    assert.match(n.evidenceRows.innerHTML,/123/);
  },
  stopped_blocked_and_limit_never_turn_pending_work_into_success() {
    for (const status of ['blocked','limit','stopped']) {
      const {ui,nodes:n} = harness();
      ui.renderTask({task_status:status,runner_state:status,steps_completed:6,tool:'restart_service',plan:['重启服务'],message:'权限拒绝，未执行。'});
      assert.equal(n.completedCount.textContent,'0');
      assert.doesNotMatch(n.planTimeline.innerHTML,/data-state="executed"/);
      assert.equal(n.taskAlert.hidden,false);
      assert.match(n.taskAlert.textContent,/权限拒绝/);
      assert.ok(n.taskNextAction.textContent.length > 0);
    }
  },
  diagnostics_and_full_model_explanation_preserve_warnings_without_html_execution() {
    const {ui,nodes:n} = harness();
    const attack='<img src=x onerror="alert(1)">';
    ui.renderTask({task_status:'complete',message:'第一句。'+attack+'\n仅只读查询，没有修复；根因未知。最后一条警告不可遗漏！',
      diagnostic_assessment:{confirmed:['[72e8aa15-d05b-4572-93e6-f746f953aafb] 剩余 1073741824 字节。'],
        hypotheses:['可能上游异常；不能确认。'],unknowns:['部分日志已截断。',attack]},
      observations:[{tool:attack,target:attack,source:attack,observed_at:attack,result_excerpt:attack,truncated:true,facts:{extra:'所有原始数据'}}]});
    for (const id of ['taskNarrative','conclusionUnknowns','evidenceRows']) {
      assert.doesNotMatch(n[id].innerHTML,/<img/);
      assert.match(n[id].innerHTML,/&lt;img/);
    }
    assert.match(n.taskNarrative.innerHTML,/最后一条警告不可遗漏/);
    assert.match(n.taskNarrative.innerHTML,/仅只读查询，没有修复/);
    assert.match(n.conclusionFacts.innerHTML,/1073741824 字节/);
    assert.doesNotMatch(n.conclusionFacts.innerHTML,/72e8aa15/);
    assert.match(n.conclusionUnknowns.innerHTML,/截断/);
    assert.match(n.taskEvidenceData.textContent,/所有原始数据/);
    assert.match(n.taskEvidenceData.textContent,/truncated/);
    for (const id of ['taskMessage','taskPlan','taskScope','taskRemaining','taskEvidence']) assert.equal(n[id].textContent,'');
  },
  empty_or_unrecognized_data_is_explicit_and_reset_clears_previous_task() {
    const {ui,nodes:n} = harness();
    ui.renderTask({task_status:'unexpected',observations:null,plan:{bad:1},message:null});
    assert.equal(n.completedCount.textContent,'0');
    assert.match(n.planTimeline.innerHTML,/尚未|暂无/);
    assert.match(n.evidenceRows.innerHTML,/暂无|尚无/);
    assert.match(n.taskNextAction.textContent,/状态|任务/);
    ui.renderTask({message:'旧任务',plan:['旧计划'],observations:[{tool:'read_log'}]});
    ui.resetTask();
    assert.doesNotMatch(n.taskNarrative.innerHTML,/旧任务/);
    assert.doesNotMatch(n.planTimeline.innerHTML,/旧计划/);
    assert.equal(n.completedCount.textContent,'0');
    assert.doesNotThrow(()=>ui.renderTask(null));
  },
  resource_chips_and_records_render_only_supplied_data_safely() {
    const {ui,nodes:n} = harness();
    ui.setBackend({execution_backend:'local_readonly',execution_resources:{services:['nginx'],log_paths:['<script>x</script>']}});
    ui.renderTask({scope:{services:['nginx'],forbidden_tools:['restart_service'],defaults:['最近20行']}});
    assert.match(n.backendResources.innerHTML,/真实只读/);
    assert.match(n.backendResources.innerHTML,/nginx/);
    assert.doesNotMatch(n.backendResources.innerHTML,/<script>/);
    assert.match(n.taskResourceDefaults.innerHTML,/最近20行/);
    assert.match(n.taskResourceChips.innerHTML,/禁止/);
    assert.equal(n.resourceScope.textContent,'');
    assert.equal(n.taskModeDescription.textContent,'');
    ui.renderRecords({approvals:[{request_id:'a',tool:'restart_service',status:'pending',requester:'<svg/onload=x>'}],
      operations:[{operation_id:'b',tool:'read_log',status:'completed'}],audit:{count:3}});
    assert.match(n.recordsRows.innerHTML,/&lt;svg/);
    assert.doesNotMatch(n.recordsRows.innerHTML,/<svg/);
    assert.match(n.recordsRows.innerHTML,/b/);
    assert.match(n.recordsMetrics.innerHTML,/3/);
    ui.renderRecords({});
    assert.match(n.recordsRows.innerHTML,/暂无/);
    ui.setBackend({});
    assert.match(n.backendResources.innerHTML,/未知|未配置|未提供/);
  },
  approval_markup_preserves_review_information_and_escapes_every_field() {
    const {ui} = harness();
    const html=ui.approvalMarkup({request_id:'request-1',tool:'update_config',requester:'<svg/onload=x>',
      arguments:{path:'/config/app.conf',content:'first line\n<script>alert(1)</script>'},reason:'需要修复配置'});
    assert.match(html,/模拟修改配置/);
    assert.match(html,/app.conf/);
    assert.match(html,/first line/);
    assert.match(html,/&lt;script/);
    assert.match(html,/&lt;svg/);
    assert.match(html,/需要修复配置/);
    assert.match(html,/request-1/);
    assert.doesNotMatch(html,/<button|onclick|<script|<svg/);
  },
  navigation_rejects_external_keys_and_keeps_api_state_untouched() {
    const {ui,nodes:n,window} = harness('#records');
    assert.equal(n['view-records'].hidden,false);
    assert.equal(n.operationRail.hidden,true);
    assert.equal(n.workspaceContent.dataset.view,'records');
    assert.equal(ui.showView('https://evil.invalid'),false);
    assert.equal(window.location.hash,'#records');
    assert.equal(ui.showView('tools'),true);
    assert.equal(n.operationRail.hidden,false);
    assert.equal(n['nav-tools'].attributes['aria-current'],'page');
    assert.equal(n['view-task'].hidden,true);
    assert.equal(window.location.hash,'#tools');
    ui.applySession({authenticated:true,role:'operator'});
    assert.equal(n.workspaceContent.dataset.view,'tools');
    n['nav-task'].listeners.click({preventDefault(){}});
    assert.equal(n.workspaceContent.dataset.view,'task');
  },
  first_approver_session_opens_approvals_but_polling_does_not_jump_views() {
    const {ui,nodes:n} = harness();
    ui.applySession({authenticated:true,role:'approver'});
    assert.equal(n.workspaceContent.dataset.view,'approvals');
    ui.showView('records');
    ui.applySession({authenticated:true,role:'approver'});
    assert.equal(n.workspaceContent.dataset.view,'records');
    const operator=harness();
    operator.ui.applySession({authenticated:true,role:'operator'});
    assert.equal(operator.nodes.workspaceContent.dataset.view,'task');
    const admin=harness();
    admin.ui.applySession({authenticated:true,role:'admin'});
    assert.equal(admin.nodes.workspaceContent.dataset.view,'task');
    const respectHash=harness('#tools');
    respectHash.ui.applySession({authenticated:true,role:'approver'});
    assert.equal(respectHash.nodes.workspaceContent.dataset.view,'tools');
  },
  tabs_support_arrow_home_end_and_correct_aria_without_navigation() {
    const {ui,nodes:n,window} = harness();
    let prevented=0;
    n['tab-plan'].listeners.keydown({key:'ArrowRight',preventDefault(){prevented++;}});
    assert.equal(n['task-panel-conclusion'].hidden,false);
    assert.equal(n['tab-conclusion'].attributes['aria-selected'],'true');
    assert.equal(n['tab-plan'].attributes.tabindex,'-1');
    assert.equal(n['tab-conclusion'].focused,true);
    assert.equal(n['tab-conclusion'].attributes['aria-controls'],'task-panel-conclusion');
    n['tab-conclusion'].listeners.keydown({key:'End',preventDefault(){prevented++;}});
    assert.equal(n['task-panel-evidence'].hidden,false);
    n['tab-evidence'].listeners.keydown({key:'Home',preventDefault(){prevented++;}});
    assert.equal(n['task-panel-plan'].hidden,false);
    n['tab-plan'].listeners.keydown({key:'ArrowLeft',preventDefault(){prevented++;}});
    assert.equal(n['task-panel-evidence'].hidden,false);
    assert.equal(prevented,4);
    assert.equal(ui.showTaskTab('<script>'),false);
    assert.equal(window.location.hash,'');
  },
  missing_dom_and_history_are_supported() {
    const {ui} = harness();
    assert.doesNotThrow(()=>{
      ui.init({getElementById:()=>null,querySelectorAll:()=>[]});
      ui.renderTask({}); ui.applySession({}); ui.renderRecords(null); ui.setBackend(null);
      ui.showView('records'); ui.showTaskTab('analysis'); ui.resetTask();
    });
    const api=require('../web/workbench.js');
    assert.equal(typeof api.renderTask,'function');
  }
};

const names = process.argv[2] ? [process.argv[2]] : Object.keys(cases);
for (const name of names) {
  assert.equal(typeof cases[name],'function','unknown test '+name);
  cases[name]();
  console.log('PASS '+name);
}
