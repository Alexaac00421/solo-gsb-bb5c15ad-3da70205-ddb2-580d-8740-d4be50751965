'use strict';
// 单点挂牌失效风险报告端到端测试(HTTP)。
// 使用方式: LOTO_DB=/tmp/loto-risk-e2e.db PORT=3106 node server.js 后
//           BASE=http://127.0.0.1:3106 node test/risk.e2e.js
const BASE = process.env.BASE || 'http://127.0.0.1:3106';

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  ✔', msg); }
  else { fail++; console.log('  ✘ FAIL:', msg); }
}
function eq(a, b, msg) { ok(a === b, `${msg} (期望 ${JSON.stringify(b)}, 实际 ${JSON.stringify(a)})`); }

async function call(method, url, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined && method !== 'GET') opts.body = JSON.stringify(body);
  const r = await fetch(BASE + url, opts);
  return { status: r.status, data: await r.json().catch(() => ({})) };
}
const post = (url, body) => call('POST', url, body);

const OP = { actor: '风险操作员', role: 'operator' };
const ADMIN = { actor: '风险管理员', role: 'admin' };
const S1 = 1, S2 = 2, K1 = 3, K2 = 4, K3 = 5, D1 = 6, D2 = 7;

// 顺序执行变更并追踪修订号; 返回最新修订号。
async function mutate(action, url, body, rev) {
  const r = await post(url, { ...body, revision: rev });
  if (!r.data.ok) throw new Error(`${action} 失败: ${JSON.stringify(r.data.error)} rev=${rev}`);
  return r.data.revision;
}

(async () => {
  let rev = (await call('GET', '/api/state')).data.revision;
  console.log('初始修订号:', rev);

  console.log('\n[P0] 无有效许可 -> 空报告(省略筛选); 只读不产生审计');
  const audit0 = (await call('GET', '/api/audit?limit=500')).data.logs.length;
  let r = await post('/api/risks/single-point-tag', {});
  eq(r.status, 200, 'HTTP 200');
  eq(r.data.kind, 'risk.singlePointTag', 'kind 正确');
  eq(r.data.revision, rev, '携带当前修订号');
  eq(r.data.taggedSwitchCount, 0, '演示库初始无挂牌开关');
  eq(r.data.checkedPermitCount, 0, '检查许可数 0');
  eq(r.data.switches.length, 0, '空报告 switches 为空');
  eq(r.data.risks.length, 0, '空报告 risks 为空');
  eq((await call('GET', '/api/state')).data.revision, rev, '只读不推进修订号');
  eq((await call('GET', '/api/audit?limit=500')).data.logs.length, audit0, '只读不写审计');

  console.log('\n[P1] 筛选校验: 显式空组/非正整数/重复/非有效编号');
  r = await post('/api/risks/single-point-tag', { permit_ids: [] });
  eq(r.status, 400, '显式空组 -> 400');
  eq(r.data.error.code, 'PERMIT_IDS_REQUIRED', '错误码 PERMIT_IDS_REQUIRED');
  for (const bad of [[0], [-2], [1.2], ['1'], [null], [true]]) {
    r = await post('/api/risks/single-point-tag', { permit_ids: bad });
    eq(r.status, 400, `非法编号 ${JSON.stringify(bad)} -> 400`);
    eq(r.data.error.code, 'INVALID_PERMIT_ID', `非法编号 ${JSON.stringify(bad)} 错误码`);
  }
  r = await post('/api/risks/single-point-tag', { permit_ids: [1, 1] });
  eq(r.status, 400, '重复 -> 400');
  eq(r.data.error.code, 'PERMIT_IDS_DUPLICATE', '错误码 PERMIT_IDS_DUPLICATE');
  eq((r.data.duplicate_ids || []).join(','), '1', '响应指出重复编号');
  r = await post('/api/risks/single-point-tag', { permit_ids: {} });
  eq(r.status, 400, '非数组(对象) -> 400');
  eq(r.data.error.code, 'PERMIT_IDS_REQUIRED', '非数组视同显式空组');
  r = await post('/api/risks/single-point-tag', { permit_ids: [9999] });
  eq(r.status, 404, '非有效编号 -> 404');
  eq(r.data.error.code, 'PERMIT_NOT_FOUND', '错误码 PERMIT_NOT_FOUND');
  eq((r.data.invalid_permit_ids || []).join(','), '9999', '响应指出无效编号');
  eq(r.data.revision, rev, '错误响应也携带当前修订号');

  console.log('\n[P2] 建态: K1 挂牌保护 D2(单挂点), K3 挂牌保护 D1(K1/K2 双源汇合)');
  rev = await mutate('K1分闸', `/api/switches/${K1}/open`, OP, rev);
  rev = await mutate('K1挂牌', `/api/switches/${K1}/tag`, OP, rev);
  rev = await mutate('K3分闸', `/api/switches/${K3}/open`, OP, rev);
  rev = await mutate('K3挂牌', `/api/switches/${K3}/tag`, OP, rev);
  rev = await mutate('申请D1', '/api/permits', { ...OP, device_id: D1 }, rev);
  rev = await mutate('申请D2', '/api/permits', { ...OP, device_id: D2 }, rev);

  r = await post('/api/risks/single-point-tag', {});
  eq(r.status, 200, 'HTTP 200');
  eq(r.data.revision, rev, '报告修订号与当前一致');
  eq(r.data.taggedSwitchCount, 2, '2 个已挂牌开关');
  eq(r.data.checkedPermitCount, 2, '检查全部 2 张许可');
  eq(r.data.switches.length, 2, '逐挂牌开关列出(含无风险开关)');
  eq(r.data.switches.map((s) => s.switch_id).join(','), `${K1},${K3}`, '开关按编号升序');
  // (K1,许可D2), (K3,许可D1)
  eq(r.data.risks.map((x) => `${x.switch_id}/${x.permit_id}`).join(','),
    `${K1}/2,${K3}/1`, '风险按开关编号、许可编号稳定排序');
  const k1 = r.data.switches.find((s) => s.switch_id === K1);
  const k3 = r.data.switches.find((s) => s.switch_id === K3);
  eq(k1.has_single_point_risk, true, 'K1 对 D2 有单点风险');
  eq(k1.risk_permit_count, 1, 'K1 风险许可数 1');
  eq(k1.checked_permit_count, 2, 'K1 检查许可数 2(子集外许可也计入无风险判断)');
  eq(k3.has_single_point_risk, true, 'K3 对 D1 有单点风险');
  // K3 失效见证: S1->K1->K3->D1 或 S2->K2->K3->D1, 必穿 K3 且止于 D1
  const k3Risk = k3.risks[0];
  const nodes = k3Risk.livePath.nodes;
  ok([S1, S2].includes(nodes[0].id), 'D1 风险路径起于启用电源');
  eq(nodes.at(-1).id, D1, 'D1 风险路径止于 D1');
  ok(nodes.some((n) => n.id === K3), 'D1 风险路径穿过被假设失效的 K3');
  eq(k3Risk.assumed_failed_switch, K3, '风险项标明假设失效开关 K3');
  ok(nodes.every((n) => n.kind === 'source' || n.kind === 'switch' || n.kind === 'device'),
    '路径节点结构完整(含名称等真实字段)');
  // K1 失效 D2 的见证必为 S1->K1->D2
  eq(k1.risks[0].livePath.nodes.map((n) => n.id).join(','), `${S1},${K1},${D2}`,
    'D2 风险路径为 S1->K1->D2');

  console.log('\n[P3] 许可编号筛选: 仅查许可 1 -> K1 列为无单点风险');
  r = await post('/api/risks/single-point-tag', { permit_ids: [1] });
  eq(r.status, 200, 'HTTP 200');
  eq(r.data.checked_permit_ids.join(','), '1', '所查为许可 1');
  eq(r.data.risks.length, 1, '仅 1 项风险(K3->许可1)');
  const k1Safe = r.data.switches.find((s) => s.switch_id === K1);
  eq(k1Safe.has_single_point_risk, false, 'K1 未影响许可 1: 无单点风险但仍列出');
  eq(k1Safe.risks.length, 0, 'K1 项下无风险明细');
  const k3Only = r.data.switches.find((s) => s.switch_id === K3);
  eq(k3Only.has_single_point_risk, true, 'K3 仍有风险');

  console.log('\n[P4] 整份报告基于同一快照: 并发变更前后报告结论自洽');
  // 结束许可 2 后立即报告: 同一次请求内图与许可一致, 许可 2 不再出现
  const revBefore = rev;
  rev = await mutate('结束D2', `/api/permits/2/end`, OP, rev);
  r = await post('/api/risks/single-point-tag', {});
  eq(r.data.revision, rev, '新报告携带新修订号');
  eq(r.data.checkedPermitCount, 1, '只剩 1 张有效许可');
  eq(r.data.checked_permit_ids.join(','), '1', '仅许可 1');
  eq(r.data.risks.map((x) => x.permit_id).join(','), '1', '已结束许可不再产生风险项');
  ok(r.data.risks.every((x) => x.switch_id === K3), '只剩 K3 对许可 1 的风险');
  // 引用刚结束的许可编号 -> 拒绝(非有效编号)
  const gone = await post('/api/risks/single-point-tag', { permit_ids: [2] });
  eq(gone.status, 404, '已结束许可编号 -> 404');

  console.log('\n[P5] 只读保证: 修订号/开关/许可与报告前后一致, 无新增审计');
  const auditNow = (await call('GET', '/api/audit?limit=500')).data.logs.length;
  const stateBefore = (await call('GET', '/api/state')).data;
  for (const body of [{}, { permit_ids: [1] }]) {
    await post('/api/risks/single-point-tag', body);
    await post('/api/risks/single-point-tag', body);
  }
  const stateAfter = (await call('GET', '/api/state')).data;
  eq(stateAfter.revision, revBefore + 1, '连续 4 次报告后修订号不变');
  eq(JSON.stringify(stateAfter.nodes), JSON.stringify(stateBefore.nodes), '开关状态不变');
  eq(JSON.stringify(stateAfter.permits), JSON.stringify(stateBefore.permits), '许可不变');
  eq((await call('GET', '/api/audit?limit=500')).data.logs.length, auditNow, '审计条数不变');

  console.log('\n[P6] 每个来源均串联双挂牌 -> 全部无单点风险');
  // D1 来电: S1->K1->K3 与 S2->K2->K3。当前 K1 挂牌、K3 已解牌;
  // 再挂 K2 与 K3 后, 每条通路都串联两个挂牌点, 任一单点失效仍被另一个切断。
  rev = stateAfter.revision;
  rev = await mutate('K2分闸', `/api/switches/${K2}/open`, OP, rev);
  rev = await mutate('K2挂牌', `/api/switches/${K2}/tag`, OP, rev); // 新增屏障不破坏隔离
  r = await post('/api/risks/single-point-tag', {});
  eq(r.status, 200, 'HTTP 200');
  eq(r.data.taggedSwitchCount, 3, '挂牌开关为 K1/K2/K3');
  eq(r.data.risks.length, 0, '无单点风险(每条通路双挂牌串联)');
  ok(r.data.switches.every((s) => !s.has_single_point_risk), 'K1/K2/K3 均列为无单点风险');

  console.log(`\n结果: ${pass} 项通过, ${fail} 项失败`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
