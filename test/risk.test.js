'use strict';

// src/risk.js 单点挂牌失效风险分析单元测试(不走 HTTP / 数据库)。
// 重点: 逐挂牌开关假设失效、完整可达性规则、风险附真实路径并穿过失效开关、
// 无单点风险开关同样列出、无许可空报告、许可筛选校验、(开关,许可)稳定排序。
// 运行: node test/risk.test.js

const assert = require('assert');
const {
  analyzeSinglePointTagRisk,
  selectPermits,
  bypassTagView
} = require('../src/risk');

let pass = 0;
function ok(cond, msg) {
  assert.ok(cond, msg);
  pass++;
  console.log('  ✔', msg);
}
function eq(a, b, msg) {
  assert.strictEqual(a, b, `${msg} (期望 ${b}, 实际 ${a})`);
  pass++;
  console.log('  ✔', msg);
}

function buildGraph(nodeSpecs, edgeSpecs) {
  const nodes = nodeSpecs.map(([id, kind, extra = {}]) => ({
    id, kind, name: `N${id}`,
    enabled: extra.enabled !== undefined ? !!extra.enabled : true,
    open_pos: !!extra.open_pos,
    tagged: !!extra.tagged
  }));
  const edges = edgeSpecs.map(([id, from, to]) => ({
    id, from, to, from_node: from, to_node: to
  }));
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const outAdj = new Map();
  for (const e of edges) {
    if (!outAdj.has(e.from_node)) outAdj.set(e.from_node, []);
    outAdj.get(e.from_node).push(e);
  }
  return { nodes, edges, nodeById, outAdj };
}

const permits = (specs) => specs.map(([id, deviceId]) => ({
  id, device_id: deviceId, status: 'active', device_name: `D${deviceId}`
}));

function expectError(fn, status, code, msg) {
  try {
    fn();
    assert.fail('应当抛出错误');
  } catch (e) {
    eq(e.status, status, `${msg}: HTTP 状态`);
    eq(e.code, code, `${msg}: 错误码`);
  }
}

console.log('\n[R1] 单一挂牌点保护两张许可: 失效后两许可均出现真实带电路径');
{
  // S1->K1->D1, S2->K2->K1, K1 为两源汇合后的唯一挂牌点
  const g = buildGraph(
    [[1, 'source'], [2, 'source'], [3, 'switch', { tagged: true }],
     [4, 'switch'], [5, 'device'], [6, 'device']],
    [[1, 1, 3], [2, 2, 4], [3, 4, 3], [4, 3, 5], [5, 3, 6]]
  );
  const ps = permits([[10, 5], [20, 6]]);
  const r = analyzeSinglePointTagRisk(g, ps);
  eq(r.taggedSwitchCount, 1, '1 个已挂牌开关');
  eq(r.switches.length, 1, '逐挂牌开关列出一项');
  eq(r.switches[0].risk_permit_count, 2, '两张许可都受单点威胁');
  eq(r.switches[0].has_single_point_risk, true, '存在单点风险');
  eq(r.risks.length, 2, '扁平清单 2 项');
  eq(r.risks[0].permit_id, 10, '按许可编号排序: 10 在前');
  for (const risk of r.risks) {
    const ids = risk.livePath.nodes;
    ok(ids[0] === 1 || ids[0] === 2, `许可 ${risk.permit_id}: 路径起于启用电源`);
    eq(ids[ids.length - 1], risk.device_id, `许可 ${risk.permit_id}: 路径止于其设备`);
    ok(ids.includes(3), `许可 ${risk.permit_id}: 路径穿过被假设失效的挂牌开关 3`);
  }
}

console.log('\n[R2] 两个挂牌点各自只威胁一张许可, 按开关编号、许可编号排序');
{
  // S1->K1(tag)->D1, S2->K2(tag)->D2: K1 失效只影响 D1, K2 失效只影响 D2
  const g = buildGraph(
    [[1, 'source'], [2, 'source'], [3, 'switch', { tagged: true }],
     [4, 'switch', { tagged: true }], [5, 'device'], [6, 'device']],
    [[1, 1, 3], [2, 3, 5], [3, 2, 4], [4, 4, 6]]
  );
  // 故意乱序传入许可, 验证报告内部排序
  const r = analyzeSinglePointTagRisk(g, permits([[20, 6], [10, 5]]));
  eq(r.switches.map((s) => s.switch_id).join(','), '3,4', '开关按编号升序');
  eq(r.risks.map((x) => [x.switch_id, x.permit_id]).map((p) => p.join('/')).join(','),
    '3/10,4/20', '扁平风险按 (开关, 许可) 排序');
  const k2 = r.switches.find((s) => s.switch_id === 4);
  eq(k2.risks[0].permit_id, 20, 'K2 失效只影响许可 20(D2)');
  eq(k2.risks[0].livePath.nodes.join(','), '2,4,6', 'K2 见证路径为 S2->K2->D2');
}

console.log('\n[R3] 串联双挂牌(冗余): 任一单点失效仍隔离, 开关列为无单点风险');
{
  // S->K1(tag)->K2(tag)->D: 任一挂牌失效, 另一个仍切断
  const g = buildGraph(
    [[1, 'source'], [2, 'switch', { tagged: true }],
     [3, 'switch', { tagged: true }], [4, 'device']],
    [[1, 1, 2], [2, 2, 3], [3, 3, 4]]
  );
  const r = analyzeSinglePointTagRisk(g, permits([[1, 4]]));
  eq(r.switches.length, 2, '两个挂牌开关都列出');
  eq(r.risks.length, 0, '无单点风险项');
  ok(r.switches.every((s) => !s.has_single_point_risk && s.risk_permit_count === 0),
    '两个开关均标记为无单点风险');
}

console.log('\n[R4] 所查许可子集中安全的挂牌开关: 不影响子集但仍逐项列出');
{
  // K1(tag) 保护 D1 与 D2; K2(tag) 只保护 D2。只查 D1 时 K2 无单点风险。
  const g = buildGraph(
    [[1, 'source'], [2, 'source'], [3, 'switch', { tagged: true }],
     [4, 'switch', { tagged: true }], [5, 'device'], [6, 'device']],
    [[1, 1, 3], [2, 3, 5], [3, 3, 6], [4, 2, 4], [5, 4, 6]]
  );
  const all = permits([[1, 5], [2, 6]]);
  const r = analyzeSinglePointTagRisk(g, [all[0]]); // 仅查 D1 的许可
  eq(r.checkedPermitCount, 1, '只检查 1 张许可');
  eq(r.switches.length, 2, '两个挂牌开关均列出(含无风险者)');
  const k1 = r.switches.find((s) => s.switch_id === 3);
  const k2 = r.switches.find((s) => s.switch_id === 4);
  eq(k1.has_single_point_risk, true, 'K1 对 D1 有单点风险');
  eq(k2.has_single_point_risk, false, 'K2 不在 D1 来电路径上: 无单点风险');
  eq(r.risks.length, 1, '扁平清单仅 1 项(K2 不出现风险项)');
  // 全量检查时: K1 失效威胁 D1(S1 路径) 与 D2(S1 路径), K2 失效威胁 D2(S2 路径)
  const rAll = analyzeSinglePointTagRisk(g, all);
  eq(rAll.risks.length, 3, '全量检查时 3 项风险(K1 同时是 D1/D2 的单点)');
  eq(rAll.risks.map((x) => [x.switch_id, x.permit_id]).map((p) => p.join('/')).join(','),
    '3/1,3/2,4/2', '全量风险仍按 (开关, 许可) 排序');
}

console.log('\n[R5] 无已挂牌开关: 空清单(所查许可非空)');
{
  const g = buildGraph(
    [[1, 'source'], [2, 'switch'], [3, 'device']],
    [[1, 1, 2], [2, 2, 3]]
  );
  const r = analyzeSinglePointTagRisk(g, permits([[1, 3]]));
  eq(r.taggedSwitchCount, 0, '无挂牌开关');
  eq(r.switches.length, 0, '无开关项');
  eq(r.risks.length, 0, '无风险项');
  eq(r.checkedPermitCount, 1, '仍记录所查许可数');
}

console.log('\n[R6] 无有效许可: 空报告(不逐项列出挂牌开关)');
{
  const g = buildGraph(
    [[1, 'source'], [2, 'switch', { tagged: true }], [3, 'device']],
    [[1, 1, 2], [2, 2, 3]]
  );
  const r = analyzeSinglePointTagRisk(g, []);
  eq(r.checkedPermitCount, 0, '检查许可数 0');
  eq(r.taggedSwitchCount, 1, '图上确有 1 个挂牌开关(仅作计数信息)');
  eq(r.switches.length, 0, '空报告不逐项列出开关');
  eq(r.risks.length, 0, '空报告无风险');
}

console.log('\n[R7] 停用电源: 失效挂牌不产生来自停用电源的风险');
{
  // S1(停用)->K1(tag)->D, S2(启用)无路径到 D: 设备本身已隔离且无启用电源来电
  const g = buildGraph(
    [[1, 'source', { enabled: false }], [2, 'source', { enabled: true }],
     [3, 'switch', { tagged: true }], [4, 'device']],
    [[1, 1, 3], [2, 3, 4]]
  );
  const r = analyzeSinglePointTagRisk(g, permits([[1, 4]]));
  eq(r.risks.length, 0, '停用电源不产生带电路径, 无单点风险');
}

console.log('\n[R8] 输入图不被修改: 失效只发生在内存视图');
{
  const g = buildGraph(
    [[1, 'source'], [2, 'switch', { tagged: true }], [3, 'device']],
    [[1, 1, 2], [2, 2, 3]]
  );
  analyzeSinglePointTagRisk(g, permits([[1, 3]]));
  eq(g.nodeById.get(2).tagged, true, '原开关仍为挂牌');
  const view = bypassTagView(g, 2);
  eq(view.nodeById.get(2).tagged, false, '内存视图中已视为未挂牌');
  eq(g.nodeById.get(2).tagged, true, '取视图后原图仍不改变');
  ok(view.edges === g.edges && view.outAdj === g.outAdj, '边与邻接表共享只读引用');
}

console.log('\n[R9] selectPermits: 省略查全部; 显式空组/非正整数/重复/非有效编号拒绝');
{
  const ps = permits([[1, 5], [2, 6]]);
  eq(selectPermits(undefined, ps).length, 2, '省略 -> 全部');
  eq(selectPermits(null, ps).length, 2, 'null 视同省略');
  eq(selectPermits([2, 1], ps).map((p) => p.id).join(','), '1,2', '筛选结果按编号升序');
  expectError(() => selectPermits([], ps), 400, 'PERMIT_IDS_REQUIRED', '显式空组');
  expectError(() => selectPermits([0], ps), 400, 'INVALID_PERMIT_ID', '编号 0');
  expectError(() => selectPermits([-1], ps), 400, 'INVALID_PERMIT_ID', '负数');
  expectError(() => selectPermits([1.5], ps), 400, 'INVALID_PERMIT_ID', '小数');
  expectError(() => selectPermits(['1'], ps), 400, 'INVALID_PERMIT_ID', '字符串数字');
  expectError(() => selectPermits([null], ps), 400, 'INVALID_PERMIT_ID', 'null 元素');
  expectError(() => selectPermits([1, 1], ps), 400, 'PERMIT_IDS_DUPLICATE', '重复编号');
  expectError(() => selectPermits([99], ps), 404, 'PERMIT_NOT_FOUND', '非有效许可编号');
}

console.log(`\n结果: ${pass} 项断言全部通过`);
