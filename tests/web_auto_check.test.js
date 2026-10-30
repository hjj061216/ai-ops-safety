const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const tick = () => new Promise(resolve => setImmediate(resolve));
async function harness(options = {}) {
  const elements = {}, handlers = {}, posts = [], requests = [], scrolls = [], clock = {now: Date.now()};
  const storage = options.storage || new Map();
  const sessionStorage = options.storageBlocked ? {getItem(){throw new Error('blocked');},setItem(){throw new Error('blocked');}}
    : {getItem:key=>storage.get(key),setItem:(key,value)=>storage.set(key,value)};
  class TestDate extends Date { static now() { return clock.now; } }
  const el = id => elements[id] ||= {
    value:'', disabled:false, hidden:false, open:false, dataset:{}, attributes:{}, textContent:'',
    setAttribute(name,value) { this.attributes[name]=value; },
    addEventListener(name,handler) { handlers[id+':'+name]=handler; }
  };
  const candidate = (id='natural',tool='get_service_status',args={name:'nginx'},risk='low') => ({actionable:true,candidate_id:id,tool,arguments:args,effective_risk:risk,expires_at:clock.now/1000+900});
  const behavior = {interpret: async()=>candidate(),check: async body=>({tool: body.tool,decision:body.candidate_id==='manual'?'require_human':'allow',effective_risk:body.candidate_id==='manual'?'medium':'low'}),...options};
  const context = vm.createContext({window:{location:options.location,crypto:webcrypto,sessionStorage,scrollTo:options=>scrolls.push(options)},Date:TestDate,AbortController,setTimeout,clearTimeout,setInterval:()=>0,document:{getElementById:el,querySelectorAll:selector=>selector==='.role-control'?[]:Object.values(elements)},fetch:async(url,request={})=>{
    requests.push({url,headers:request.headers});
    const body=request.body?JSON.parse(request.body):{};
    if(request.method==='POST')posts.push({url,body,headers:request.headers});
    let data;
    if(url==='/api/session')data=behavior.session||{authenticated:false};
    else if(url==='/api/status')data={approvals:[],operations:[],audit:{count:0},...(typeof behavior.status==='function' ? await behavior.status() : behavior.status||{})};
    else if(url==='/api/login')data=await behavior.login(body,request);
    else if(url.startsWith('/api/tasks/'))data=await behavior.task(url,body);
    else if(url==='/api/interpret')data=await behavior.interpret(body);
    else if(url==='/api/check')data=await behavior.check(body);
    else if(url==='/api/candidates/manual')data=candidate('manual',body.tool,body.arguments,'medium');
    else if(url==='/api/approvals/request')data={request_id:'approval-1'};
    else if(url==='/api/approvals/approve')data={approval_token:'private-approval-token'};
    else if(url==='/api/execute')data=behavior.execute || {executed:true,decision:{tool:body.tool},operation:{operation_id:'operation-1',result:{name:'nginx',status:'running'},rollback_available:false}};
    else data={approvals:[],operations:[],audit:{count:0}};
    return {ok:true,status:200,json:async()=>({ok:true,data})};
  }});
  vm.runInContext(fs.readFileSync(path.join(__dirname,'..','web','workbench.js'),'utf8'),context);
  vm.runInContext(script,context);await tick();
  el('naturalRequest').value='查看 nginx 服务状态';el('role').value='viewer';
  el('manualTool').value='get_service_status';el('serviceName').value='nginx';
  el('requester').value='alice';el('reason').value='test';el('approver').value='bob';el('approverRole').value='admin';
  return {ui:context.window.opsConsole,context,el,posts,requests,storage,handlers,behavior,clock,candidate,scrolls};
}
const cases = {
  async login_enters_workspace_at_top_without_jumping_on_later_session_updates() {
    const h=await harness({login:async()=>({authenticated:true,csrf:'fixture',username:'alice',role:'operator'})});
    h.el('loginUser').value='alice';h.el('loginPassword').value='synthetic-password';
    await h.ui.submitLogin({preventDefault(){}});
    assert.equal(h.el('workspace').hidden,false);
    assert.ok(h.scrolls.some(value=>value.top===0));
    h.scrolls.length=0;
    vm.runInContext("applySession({authenticated:true,csrf:'fixture',username:'alice',role:'operator'})",h.context);
    assert.equal(h.scrolls.length,0);
  },
  async compatible_model_label_uses_active_host_and_model_without_deepseek_defaults() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'openai_compatible',model:'independent-model',endpoint_host:'gateway.example',api_key_configured:true,configuration_state:'active'}}});
    assert.match(h.el('modelStatus').textContent,/兼容 API/);
    assert.match(h.el('modelStatus').textContent,/independent-model/);
    assert.match(h.el('modelStatus').textContent,/gateway\.example/);
    assert.doesNotMatch(h.el('modelStatus').textContent,/DeepSeek|deepseek-flash|已连接/);
    assert.match(h.el('modelConfigNote').textContent,/重启/);
  },
  async pending_model_settings_keep_current_model_and_visible_restart_note() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'openai_compatible',model:'loaded-model',api_key_configured:true,configuration_state:'restart_required'}}});
    assert.match(h.el('modelStatus').textContent,/当前生效.*loaded-model/);
    assert.match(h.el('modelConfigNote').textContent,/配置.*变更.*重启/);
    assert.equal(h.el('modelConfigNote').dataset.kind,'warning');
    h.behavior.status={natural_language:{provider:'ollama',model:'local-new-model',configuration_state:'active'}};
    await vm.runInContext('refreshStatus(false)',h.context);
    assert.match(h.el('modelStatus').textContent,/本地 Ollama.*local-new-model/);
    assert.doesNotMatch(h.el('modelStatus').textContent,/loaded-model|DeepSeek/);
    assert.notEqual(h.el('modelConfigNote').dataset.kind,'warning');
  },
  async invalid_config_update_and_status_failure_do_not_claim_new_config_is_active() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'deepseek',model:'loaded-model',configuration_state:'invalid_update'}}});
    assert.match(h.el('modelConfigNote').textContent,/新配置.*无效.*仍使用/);
    h.behavior.status=async()=>{throw new Error('test connection failure');};
    await vm.runInContext('refreshStatus(false)',h.context);
    assert.match(h.el('modelStatus').textContent,/暂无法读取/);
    assert.doesNotMatch(h.el('modelStatus').textContent,/loaded-model/);
  },
  async missing_generic_key_guides_its_own_config_variable() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'openai_compatible',model:'independent-model',api_key_configured:false,configuration_state:'active'}}});
    assert.match(h.el('modelConfigNote').textContent,/未配置.*LLM_API_KEY/);
    assert.doesNotMatch(h.el('modelConfigNote').textContent,/DEEPSEEK_API_KEY/);
  },
  async recovered_poll_clears_only_its_own_warning() {
    let failed=true;
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},task:async url=>{
      if(url.includes('/start'))return {task_id:'task-1',task_status:'propose',plan:['检查'],message:'准备检查',steps_completed:0,...h.candidate('safe')};
      if(failed)throw new Error('短暂断开');
      return {task_id:'task-1',task_status:'complete',runner_state:'complete',message:'已完成',plan:[],steps_completed:1,observations:[{tool:'get_service_status'}]};
    }});
    await h.ui.runTask('start');await h.ui.pollAutoTask();
    assert.equal(h.el('globalNotice').hidden,false);
    failed=false;await h.ui.pollAutoTask();
    assert.equal(h.el('globalNotice').hidden,true);
    vm.runInContext("showNotice('可能部分完成，请勿重复提交','error','execution')",h.context);
    await h.ui.pollAutoTask();
    assert.equal(h.el('globalNotice').hidden,false);
    assert.match(h.el('globalNoticeText').textContent,/可能部分完成/);
  },
  async record_tabs_support_keyboard_and_audit_result_is_visible() {
    const h=await harness();
    h.el('globalNotice').hidden=true;
    vm.runInContext("window.WorkbenchUI.showView('records')",h.context);
    let prevented=false;
    h.handlers['record-tab-summary:keydown']({key:'ArrowRight',preventDefault(){prevented=true;}});
    assert.equal(prevented,true);
    assert.equal(h.el('record-panel-raw').hidden,false);
    assert.equal(h.el('record-tab-summary').attributes.tabindex,'-1');
    await vm.runInContext('verifyAudit()',h.context);
    assert.equal(h.el('globalNotice').hidden,false);
    assert.match(h.el('globalNoticeText').textContent,/审计|哈希/);
  },
  async task_poll_failure_and_stop_failure_are_visible_outside_hidden_legacy_state() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},task:async url=>{
      if(url.includes('/start'))return {task_id:'task-1',task_status:'propose',autonomy:'read_only',plan:['检查'],message:'准备检查',steps_completed:0,...h.candidate('safe')};
      throw new Error('测试连接中断');
    }});
    h.el('globalNotice').hidden=true;
    await h.ui.runTask('start'); await h.ui.pollAutoTask();
    assert.equal(h.el('globalNotice').hidden,false);
    assert.match(h.el('globalNoticeText').textContent,/读取任务状态失败/);
    await vm.runInContext('stopAutoTask()',h.context);
    assert.match(h.el('globalNoticeText').textContent,/停止失败/);
  },
  async readonly_backend_shows_resource_scope_and_separates_facts_from_hypotheses() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{execution_backend:'local_readonly',execution_resources:{services:['nginx'],log_paths:['/var/log/nginx/error.log']}},
      task:async()=>({task_id:'real-task',task_status:'complete',runner_state:'complete',autonomy:'read_only',message:'诊断完成，未执行修复',plan:[],steps_completed:2,
        execution_backend:'local_readonly',diagnostic_assessment:{confirmed:['HTTP 503'],hypotheses:['上游可能不可达'],unknowns:['根因尚未确认']},
        observations:[{tool:'get_service_status',target:'nginx',observed_at:'2026-10-29T00:00:00Z',source:'http://127.0.0.1:8766/health',result_excerpt:'HTTP 503'},
          {tool:'read_log',target:'/var/log/nginx/error.log',observed_at:'2026-10-29T00:00:01Z',source:'configured log',result_excerpt:'connection refused'}]})});
    assert.equal(h.el('executionBadge').textContent,'真实只读');
    assert.match(h.el('resourceScope').textContent,/nginx/);
    await h.ui.runTask('start');
    assert.equal(h.el('diagnosticAssessment').hidden,false);
    assert.match(h.el('diagnosticFacts').textContent,/HTTP 503/);
    assert.match(h.el('diagnosticHypotheses').textContent,/可能不可达/);
    assert.match(h.el('diagnosticUnknowns').textContent,/尚未确认/);
    assert.match(h.el('taskEvidence').textContent,/8766\/health/);
    assert.match(h.el('taskEvidence').textContent,/2026-10-29/);
    assert.match(h.el('executionStatus').textContent,/自主任务.*2.*步/);
    assert.doesNotMatch(h.el('executionStatus').textContent,/尚未/);
  },
  async real_health_execution_does_not_display_simulated_service_state() {
    const h=await harness({execute:{executed:true,decision:{tool:'get_service_status'},operation:{operation_id:'probe-1',rollback_available:false,
      result:{backend:'local_readonly',name:'nginx',status:'http_error',healthy:false,http_status:503,latency_ms:12,
        source:'http://127.0.0.1:8766/health',observed_at:'2026-10-29T00:00:00Z'}}}});
    await h.ui.interpretRequest();await h.ui.executeCall();
    assert.match(h.el('executionSummary').textContent,/HTTP 503/);
    assert.match(h.el('executionSummary').textContent,/8766\/health/);
    assert.doesNotMatch(h.el('executionSummary').textContent,/模拟|undefined/);
  },
  async tab_selector_survives_reload_but_is_different_in_new_tab() {
    const first=await harness(), refreshed=await harness({storage:first.storage}), second=await harness();
    const selector=first.requests[0].headers['X-Console-Tab'];
    assert.match(selector,/^[a-f0-9]{32}$/);
    assert.equal(refreshed.requests[0].headers['X-Console-Tab'],selector);
    assert.notEqual(second.requests[0].headers['X-Console-Tab'],selector);
    first.el('loginUser').value='alice';first.el('loginPassword').value='fixture-password';
    first.behavior.login=async()=>({authenticated:true,csrf:'secret-csrf',username:'alice',role:'operator'});
    await first.ui.login();await first.ui.generateManualCandidate();
    for(const request of first.requests) assert.equal(request.headers['X-Console-Tab'],selector);
    assert.deepEqual([...first.storage.values()],[selector]);
  },
  async blocked_tab_storage_still_uses_independent_memory_selector() {
    const first=await harness({storageBlocked:true}), second=await harness({storageBlocked:true});
    const selector=first.requests[0].headers['X-Console-Tab'];
    assert.match(selector,/^[a-f0-9]{32}$/);
    assert.notEqual(second.requests[0].headers['X-Console-Tab'],selector);
    await first.ui.generateManualCandidate();
    for(const request of first.requests) assert.equal(request.headers['X-Console-Tab'],selector);
  },
  async cloud_provider_is_visible_without_confusing_execution_location() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'deepseek',model:'deepseek-flash',api_key_configured:true}}});
    assert.match(h.el('modelStatus').textContent,/DeepSeek API/);
    assert.match(h.el('modelStatus').textContent,/deepseek-flash/);
    assert.equal(h.el('executionBadge').textContent,'本地模拟');
  },
  async missing_cloud_key_is_explained_in_workspace() {
    const h=await harness({session:{authenticated:true,csrf:'fixture',username:'alice',role:'operator'},
      status:{natural_language:{provider:'deepseek',model:'deepseek-flash',api_key_configured:false}}});
    const message=h.el('modelStatus').textContent+' '+h.el('modelConfigNote').textContent;
    assert.match(message,/未配置/);
    assert.match(message,/后端/);
  },
  async task_scope_and_defaults_are_visible_and_completion_disables_run() {
    const h=await harness({task:async()=>({task_id:'scope-task',task_status:'complete',runner_state:'complete',autonomy:'read_only',message:'已按实际结果总结',plan:[],steps_completed:1,
      scope:{services:['nginx'],forbidden_tools:['restart_service'],defaults:['默认读取最近20行']},observations:[{tool:'read_log',target:'/var/log/nginx/error.log',result_excerpt:'演示日志'}]})});
    await h.ui.runTask('start');
    assert.equal(h.el('taskStage').textContent,'任务已完成');
    assert.match(h.el('taskScope').textContent,/nginx/); assert.match(h.el('taskScope').textContent,/禁止：模拟重启服务/);
    assert.match(h.el('taskScope').textContent,/默认读取最近20行/);
    assert.match(h.el('taskEvidence').textContent,/演示日志/);
    assert.equal(h.el('taskRunButton').disabled,true);
    assert.equal(h.el('executeButton').disabled,true);
  },
  async task_failure_separates_explanation_from_technical_detail() {
    const h=await harness({task:async()=>({task_id:'failed-task',task_status:'blocked',message:'请启动 Ollama 后重新创建任务',plan:[],steps_completed:0,diagnostic:'connection refused'})});
    await h.ui.runTask('start');
    assert.match(h.el('taskMessage').textContent,/请启动 Ollama/);
    assert.equal(h.el('taskDiagnosticPanel').hidden,false);
    assert.equal(h.el('taskDiagnostic').textContent,'connection refused');
    assert.equal(h.el('taskRunButton').disabled,true);
  },
  async unsupported_task_has_clear_state_without_tool_calls() {
    const h=await harness({task:async()=>({task_id:'unsupported-task',task_status:'unsupported',message:'当前工具未支持该操作',plan:[],steps_completed:0})});
    await h.ui.runTask('start');
    assert.equal(h.el('taskStage').textContent,'当前能力暂不支持');
    assert.equal(h.el('taskClarification').hidden,true);
    assert.equal(h.el('taskRunButton').disabled,true);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute' || v.url==='/api/check').length,0);
  },
  async login_blank_fields_have_visible_feedback() {
    const h=await harness();await h.ui.login();
    assert.equal(h.el('loginMessage').textContent,'请输入用户名和密码。');
    assert.equal(h.posts.length,0);
  },
  async login_submit_shows_loading_blocks_duplicates_and_opens_workspace() {
    let finish;
    const h=await harness({login:()=>new Promise(resolve=>{finish=resolve;})});
    h.el('loginUser').value='alice';h.el('loginPassword').value='fixture-password';
    let prevented=false;
    const pending=h.ui.submitLogin({preventDefault(){prevented=true;}});
    assert.equal(prevented,true);
    assert.equal(h.el('loginButton').disabled,true);
    assert.equal(h.el('loginButton').textContent,'登录中…');
    await h.ui.login();assert.equal(h.posts.filter(p=>p.url==='/api/login').length,1);
    finish({authenticated:true,csrf:'csrf-fixture',username:'alice',role:'operator'});await pending;
    assert.equal(h.el('workspace').hidden,false);assert.equal(h.el('loginPanel').hidden,true);
    assert.equal(h.el('loginPassword').value,'');assert.equal(h.el('loginButton').disabled,false);
  },
  async login_connection_failure_is_visible_and_retryable() {
    const h=await harness({login:async()=>{const error=new Error('fetch failed');error.name='TypeError';throw error;}});
    h.el('loginUser').value='alice';h.el('loginPassword').value='fixture-password';await h.ui.login();
    assert.equal(h.el('loginMessage').textContent.includes('无法连接'),true);
    assert.equal(h.el('loginConnectionHelp').hidden,false);assert.equal(h.el('loginButton').disabled,false);
    h.behavior.login=async()=>({authenticated:true,csrf:'csrf-fixture',username:'alice',role:'operator'});
    await h.ui.login();assert.equal(h.el('workspace').hidden,false);
  },
  async login_timeout_has_actionable_feedback() {
    const h=await harness({login:async()=>{const error=new Error('aborted');error.name='AbortError';throw error;}});
    h.el('loginUser').value='alice';h.el('loginPassword').value='fixture-password';await h.ui.login();
    assert.equal(h.el('loginMessage').textContent.includes('连接超时'),true);
    assert.equal(h.el('loginButton').disabled,false);
  },
  async late_session_probe_cannot_hide_successful_login() {
    let finishSession;
    const h=await harness({session:new Promise(resolve=>{finishSession=resolve;}),login:async()=>({authenticated:true,csrf:'csrf-fixture',username:'alice',role:'operator'})});
    h.el('loginUser').value='alice';h.el('loginPassword').value='fixture-password';await h.ui.login();
    finishSession({authenticated:false});await tick();
    assert.equal(h.el('workspace').hidden,false);assert.equal(h.el('loginPanel').hidden,true);
  },
  async file_preview_explains_why_login_is_unavailable() {
    const h=await harness({location:{protocol:'file:'}});
    h.el('loginUser').value='alice';h.el('loginPassword').value='fixture-password';await h.ui.login();
    assert.equal(h.el('loginButton').disabled,true);
    assert.equal(h.el('loginMessage').textContent.includes('文件预览'),true);
    assert.equal(h.posts.length,0);
  },
  async authenticated_requests_use_session_and_strip_identity_fields() {
    const h=await harness({session:{authenticated:true,csrf:'csrf-fixture',username:'alice',role:'operator'}});
    await h.ui.generateManualCandidate();await h.ui.requestApproval();
    assert.equal(h.el('workspace').hidden,false);
    for(const post of h.posts) {
      assert.equal(post.headers['X-CSRF-Token'],'csrf-fixture');
      assert.equal('role' in post.body,false);
      assert.equal('requester' in post.body,false);
    }
  },
  async autonomous_task_polls_server_without_browser_executing_steps() {
    let polls=0;
    const h=await harness({session:{authenticated:true,csrf:'csrf-fixture',username:'alice',role:'operator'},task:async(url)=>{
      if(url.includes('/state')) {
        polls++;
        return polls===1 ? {task_id:'task-1',runner_state:'running',task_status:'propose',message:'自动查询中',plan:['检查'],steps_completed:0,...h.candidate('auto-step')}
          : {task_id:'task-1',runner_state:'complete',task_status:'complete',message:'已完成并核验',plan:[],steps_completed:2,observations:[{tool:'read_log'}]};
      }
      return {task_id:'task-1',runner_state:'idle',task_status:'propose',message:'计划已生成',plan:['检查'],steps_completed:0,...h.candidate('initial-step')};
    }});
    h.el('taskAutonomy').checked=true;
    await h.ui.runTask('start');await h.ui.startAutoTask();
    assert.equal(h.el('executeButton').disabled,true);
    await h.ui.pollAutoTask();
    assert.equal(h.el('taskMessage').textContent.includes('已完成并核验'),true);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
    assert.equal(h.posts.filter(v=>v.url==='/api/tasks/run').length,1);
  },
  async task_clarification_and_result_driven_continuation() {
    let turn=0;
    const h=await harness({task:async(url,body)=>{
      turn++;
      if(turn===1)return {task_id:'task-1',task_status:'clarify',message:'检查哪个服务？',plan:['确认服务'],steps_completed:0};
      if(turn===2)return {task_id:'task-1',task_status:'propose',message:'查看状态',plan:['查看状态'],steps_completed:0,...h.candidate('task-candidate')};
      return {task_id:'task-1',task_status:'complete',message:'模拟服务运行中',plan:['已检查'],steps_completed:1,observations:[{tool:'get_service_status'}]};
    }});
    h.el('taskRequest').value='排查服务异常';await h.ui.runTask('start');
    assert.equal(h.el('taskClarification').hidden,false);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
    h.el('taskAnswer').value='nginx';await h.ui.runTask('reply');
    assert.equal(h.el('executeButton').disabled,false);
    assert.equal(h.el('taskContinueButton').disabled,true);
    await h.ui.executeCall();
    assert.equal(h.el('taskContinueButton').disabled,false);
    await h.ui.runTask('continue');
    assert.equal(h.el('taskMessage').textContent,'模拟服务运行中');
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,1);
  },
  async task_input_change_clears_previous_candidate() {
    const h=await harness({task:async()=>({task_id:'task-1',task_status:'propose',message:'查询',plan:['查询'],steps_completed:0,...h.candidate('task-candidate')})});
    await h.ui.runTask('start');h.ui.resetTask();
    assert.equal(h.ui.getState().candidate,null);
    assert.equal(h.el('executeButton').disabled,true);
    assert.equal(h.el('taskContinueButton').disabled,true);
  },
  async normal_two_actions() {
    const h=await harness();await h.ui.interpretRequest();
    assert.deepEqual(h.posts.map(v=>v.url),['/api/interpret','/api/check']);
    assert.equal(h.ui.getState().checked,true);assert.equal(h.ui.getState().checkDecision,'allow');
    assert.equal(h.el('executeButton').disabled,false);assert.match(h.el('feedbackDetails').textContent,/preparation/);
    assert.match(h.el('feedbackDetails').textContent,/check/);assert.match(h.el('executionStatus').textContent,/^$/);
    await h.ui.executeCall();assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,1);
    assert.equal(h.ui.getState().candidate,null);
  },
  async manual_auto_check() {
    const h=await harness();await h.ui.generateManualCandidate();
    assert.deepEqual(h.posts.map(v=>v.url),['/api/candidates/manual','/api/check']);
    assert.equal(h.ui.getState().checkDecision,'require_human');assert.equal(h.el('approvalPanel').hidden,false);
    assert.equal(h.el('executeButton').disabled,true);assert.equal(h.el('requestApprovalButton').disabled,false);
  },
  async approval_required_no_auto_execute() {
    const h=await harness({check:async()=>({decision:'require_human',effective_risk:'high'})});
    await h.ui.interpretRequest();await h.ui.executeCall();
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
    await h.ui.requestApproval();await h.ui.approveRequest();
    assert.equal(h.ui.getState().hasApprovalToken,true);assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
    await h.ui.executeCall();assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,1);
    assert.equal(h.el('feedbackDetails').textContent.includes('private-approval-token'),false);
  },
  async denied_never_executes() {
    const h=await harness({check:async()=>({decision:'deny',effective_risk:'high',reasons:['当前角色无权限']})});
    await h.ui.interpretRequest();await h.ui.executeCall();
    assert.equal(h.ui.getState().checkDecision,'deny');assert.equal(h.el('executeButton').disabled,true);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);assert.match(h.el('candidateStatus').textContent,/无权限/);
  },
  async no_candidate_skips_check() {
    const h=await harness({interpret:async()=>({actionable:false,message:'结构验证失败'})});
    await h.ui.interpretRequest();assert.equal(h.ui.getState().candidate,null);
    assert.deepEqual(h.posts.map(v=>v.url),['/api/interpret']);assert.equal(h.el('executeButton').disabled,true);
    assert.match(h.el('candidateStatus').textContent,/未生成可检查/);
  },
  async check_error_is_closed() {
    const h=await harness({check:async()=>{throw new Error('权限检查服务异常');}});
    await h.ui.interpretRequest();
    assert.equal(h.ui.getState().checked,false);assert.equal(h.ui.getState().checkDecision,null);
    assert.match(h.el('analysisMessage').textContent,/权限检查未完成/);assert.match(h.el('feedbackDetails').textContent,/permission_check/);
    await h.ui.executeCall();
    assert.equal(h.el('executeButton').disabled,true);assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
  },
  async check_timeout_is_closed() {
    const h=await harness({check:async()=>{throw new Error('权限检查请求超时');}});
    await h.ui.interpretRequest();assert.equal(h.ui.getState().checked,false);assert.equal(h.ui.getState().hasApprovalToken,false);
    assert.equal(h.el('executeButton').disabled,true);assert.match(h.el('feedbackMessage').textContent,/超时/);
  },
  async unknown_decision_is_closed() {
    const h=await harness({check:async()=>({decision:'maybe_allow',effective_risk:'low'})});
    await h.ui.interpretRequest();assert.equal(h.ui.getState().checked,false);
    assert.equal(h.el('executeButton').disabled,true);assert.match(h.el('feedbackMessage').textContent,/有效权限决策/);
  },
  async unknown_risk_is_closed() {
    const h=await harness({check:async()=>({decision:'allow',effective_risk:'safe'})});
    await h.ui.interpretRequest();assert.equal(h.ui.getState().checked,false);assert.equal(h.el('executeButton').disabled,true);
    assert.match(h.el('feedbackMessage').textContent,/未知风险等级/);
  },
  async candidate_expires_during_check() {
    const h=await harness();h.behavior.check=async()=>{h.clock.now+=901000;return {decision:'allow',effective_risk:'low'};};
    await h.ui.interpretRequest();assert.equal(h.ui.getState().candidate,null);assert.equal(h.el('executeButton').disabled,true);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
  },
  async double_click_is_serialized() {
    const h=await harness();let finish;
    h.behavior.check=()=>new Promise(resolve=>{finish=resolve;});
    const pending=h.ui.interpretRequest();while(!finish)await tick();
    assert.equal(h.ui.getState().busy,true);assert.equal(h.el('executeButton').disabled,true);
    await h.ui.interpretRequest();await h.ui.executeCall();assert.equal(h.ui.setMode('manual'),false);
    assert.equal(h.posts.filter(v=>v.url==='/api/interpret').length,1);assert.equal(h.posts.filter(v=>v.url==='/api/check').length,1);
    assert.equal(h.posts.filter(v=>v.url==='/api/execute').length,0);
    finish({decision:'allow',effective_risk:'low'});await pending;assert.equal(h.el('executeButton').disabled,false);
  },
  async changed_input_clears_permission() {
    const h=await harness();await h.ui.interpretRequest();
    h.el('naturalRequest').value='另一个请求';h.handlers['naturalRequest:input']();
    assert.equal(h.ui.getState().candidate,null);assert.equal(h.ui.getState().checked,false);assert.equal(h.el('executeButton').disabled,true);
  },
  async recheck_failure_clears_old_grant() {
    const h=await harness();await h.ui.generateManualCandidate();await h.ui.requestApproval();await h.ui.approveRequest();
    assert.equal(h.ui.getState().hasApprovalToken,true);
    h.behavior.check=async()=>{throw new Error('复查异常');};await h.ui.checkCall();
    assert.equal(h.ui.getState().checked,false);assert.equal(h.ui.getState().hasApprovalToken,false);
    assert.equal(h.ui.getState().requestId,'');assert.equal(h.el('executeButton').disabled,true);
  },
  async client_never_sends_risk() {
    const h=await harness();await h.ui.interpretRequest();await h.ui.executeCall();
    await h.ui.generateManualCandidate();await h.ui.requestApproval();await h.ui.approveRequest();await h.ui.executeCall();
    for(const request of h.posts)for(const key of ['risk','llm_risk','effective_risk','approved'])assert.equal(Object.hasOwn(request.body,key),false);
  }
};
async function main(){const names=process.argv[2]?[process.argv[2]]:Object.keys(cases);for(const name of names){assert.ok(cases[name],name);await cases[name]();console.log('PASS '+name);}}
main().catch(error=>{console.error(error);process.exitCode=1;});
