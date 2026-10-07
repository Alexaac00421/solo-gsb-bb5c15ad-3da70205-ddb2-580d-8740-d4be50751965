'use strict';

// 单点挂牌失效风险分析（只读）。
//
// 场景: 操作员想知道每张有效检修许可对“单个挂牌点失效”的暴露程度。
// 对每个当前已挂牌开关, 假设它不再阻断供电(挂牌单点失效), 其余开关状态与
// 供电图保持原状, 然后按与许可保护完全相同的“现有完整可达性规则”
// (src/graph.js 的 findReachableTarget: 多源 BFS、挂牌开关为不可穿过屏障、
// 无数量/长度上限) 判断哪些所查许可会重新出现未切断(带电)通路。
//
// 关键约定:
//   - 判定只走完整可达性分析, 绝不使用带 200 条 / 64 节点上限的诊断枚举,
//     因此结论不受诊断路径展示上限影响;
//   - 每个风险附一条真实带电路径(BFS 见证路径, 完整分析给出的最短路径),
//     路径必然穿过被假设失效的那个挂牌开关;
//   - 纯函数: 输入图不做任何修改, 失效只发生在内存视图里;
//   - 结果稳定排序: 开关按编号升序, 风险按 (开关编号, 许可编号) 升序。

const { findReachableTarget } = require('./graph');

/**
 * 构造“指定开关挂牌失效”的内存视图: 仅覆盖该开关节点(tagged=false),
 * 其余节点对象与边 / 邻接表全部共享只读引用, 不触碰原始图。
 */
function bypassTagView(graph, switchId) {
  const nodeById = new Map();
  for (const n of graph.nodes) {
    nodeById.set(n.id, n.id === switchId ? { ...n, tagged: false } : n);
  }
  return {
    nodes: graph.nodes.map((n) => (n.id === switchId ? nodeById.get(n.id) : n)),
    edges: graph.edges,
    nodeById,
    outAdj: graph.outAdj
  };
}

/**
 * 解析许可编号筛选。
 *   - 省略(null/undefined): 检查全部有效许可;
 *   - 显式空数组、非正整数 / 非整数 / 非数字、重复编号: 400;
 *   - 非当前有效许可编号: 404。
 * 与 orders/server 中鸭子类型错误约定一致(status/code + 附加字段)。
 * @returns 按编号升序排列的有效许可对象数组
 */
function selectPermits(rawFilter, activePermitList) {
  if (rawFilter === undefined || rawFilter === null) {
    return activePermitList.slice().sort((a, b) => a.id - b.id);
  }
  if (!Array.isArray(rawFilter) || rawFilter.length === 0) {
    throw Object.assign(new Error('必须提供非空许可编号集合 permit_ids(或省略该字段以检查全部有效许可)'), {
      status: 400,
      code: 'PERMIT_IDS_REQUIRED'
    });
  }
  const ids = [];
  for (const value of rawFilter) {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
      throw Object.assign(new Error(`许可编号无效: ${JSON.stringify(value)}`), {
        status: 400,
        code: 'INVALID_PERMIT_ID'
      });
    }
    ids.push(value);
  }
  const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (duplicates.length > 0) {
    throw Object.assign(new Error(`许可编号集合不能重复: ${[...new Set(duplicates)].join(', ')}`), {
      status: 400,
      code: 'PERMIT_IDS_DUPLICATE',
      duplicate_ids: [...new Set(duplicates)]
    });
  }
  const byId = new Map(activePermitList.map((p) => [p.id, p]));
  const invalid = ids.filter((id) => !byId.has(id));
  if (invalid.length > 0) {
    throw Object.assign(new Error(`有效检修许可不存在: ${invalid.join(', ')}`), {
      status: 404,
      code: 'PERMIT_NOT_FOUND',
      invalid_permit_ids: invalid
    });
  }
  return ids.sort((a, b) => a - b).map((id) => byId.get(id));
}

function deviceNameOf(graph, permit) {
  if (permit.device_name) return permit.device_name;
  const node = graph.nodeById.get(permit.device_id);
  return node ? node.name : null;
}

/**
 * 单点挂牌失效风险分析(纯函数, 不修改输入)。
 * @param {Object} graph loadGraph() 风格的完整供电图
 * @param {Array} permits 已选定(筛选后)的有效许可集合
 * @returns {{
 *   taggedSwitchCount:number, checkedPermitCount:number,
 *   switches:Array, risks:Array
 * }}
 *   switches[] 每个当前已挂牌开关一项(含无单点风险的开关), risks 为扁平化、
 *   按 (switch_id, permit_id) 稳定排序的全部风险项, 每项含真实带电路径。
 *   所查许可集合为空(即当前无有效许可)时返回空报告: switches/risks 均为空。
 */
function analyzeSinglePointTagRisk(graph, permits) {
  const selected = permits.slice().sort((a, b) => a.id - b.id);
  const taggedSwitches = graph.nodes
    .filter((n) => n.kind === 'switch' && n.tagged)
    .sort((a, b) => a.id - b.id);

  const switches = [];
  const risks = [];

  if (selected.length > 0) {
    for (const sw of taggedSwitches) {
      // 该开关挂牌失效后的假设图; 其余开关与拓扑原状不动。
      const view = bypassTagView(graph, sw.id);
      const switchRisks = [];
      for (const permit of selected) {
        // 现有完整可达性规则: 多源 BFS, 无数量/长度上限。
        const { reachable, witness } = findReachableTarget(view, permit.device_id);
        if (reachable && witness) {
          switchRisks.push({
            permit_id: permit.id,
            device_id: permit.device_id,
            device_name: deviceNameOf(graph, permit),
            livePath: witness
          });
        }
      }
      switchRisks.sort((a, b) => a.permit_id - b.permit_id);
      for (const r of switchRisks) {
        risks.push({ switch_id: sw.id, switch_name: sw.name, ...r });
      }
      switches.push({
        switch_id: sw.id,
        name: sw.name,
        checked_permit_count: selected.length,
        risk_permit_count: switchRisks.length,
        has_single_point_risk: switchRisks.length > 0,
        risks: switchRisks
      });
    }
  }

  return {
    taggedSwitchCount: taggedSwitches.length,
    checkedPermitCount: selected.length,
    switches,
    risks
  };
}

module.exports = {
  bypassTagView,
  selectPermits,
  analyzeSinglePointTagRisk
};
