import {useState} from 'react'
import {AuditEntry, usePoll} from '../api'
import {ErrorBanner} from '../App'

const ACTION_LABEL: Record<string, string> = {
  'login': '登录', 'logout': '退出', 'reauth': '再次验证口令', 'server/start': '服务启动', 'server/stop': '服务停止',
  'hosts/save': '保存主机', 'hosts/delete': '删除主机', 'hosts/test': '测试连接', 'hosts/probe': '读取主机指纹',
  'hosts/connect': '连接主机', 'hosts/disconnect': '断开主机',
  'ufw/preview': '预览 ufw 修改', 'ufw/apply': '修改 ufw', 'firewalld/preview': '预览 firewalld 修改', 'firewalld/apply': '修改 firewalld',
}
const RESULT: Record<string, [string, string]> = {ok: ['good', '成功'], error: ['crit', '失败'], denied: ['warn', '拒绝']}

function detailText(e: AuditEntry): string {
  const d = e.detail || {}
  const parts: string[] = []
  const cmds = d.commands as string[][] | undefined
  if (Array.isArray(cmds) && cmds.length) parts.push(cmds.map(c => Array.isArray(c) ? c.join(' ') : String(c)).join('；'))
  for (const [k, v] of Object.entries(d)) {
    if (k === 'commands') continue
    parts.push(`${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
  }
  return parts.join(' · ')
}

/** 审计日志（服务器版，管理员）：谁、什么时候、从哪个 IP、对哪台主机做了什么。 */
export default function AuditPage() {
  const [limit, setLimit] = useState(200)
  const [onlyChanges, setOnlyChanges] = useState(false)
  const {data, error} = usePoll<{entries: AuditEntry[]}>('/api/audit?limit=' + limit, 15000)
  let rows = data?.entries || []
  if (onlyChanges) rows = rows.filter(e => /apply|save|delete/.test(e.action))
  return (
    <div className="page">
      <div className="page-head">
        <div><h1>审计日志</h1><p>登录、主机纳管和防火墙修改的记录。完整日志在服务器数据目录的 audit.log，也会写到服务日志里</p></div>
        <span className="sp"/>
        <label className="dim" style={{display: 'flex', gap: 6, alignItems: 'center'}}>
          <input type="checkbox" checked={onlyChanges} onChange={e => setOnlyChanges(e.target.checked)}/> 只看修改
        </label>
      </div>
      <ErrorBanner error={error}/>
      <div className="card">
        {rows.length ? <div className="tbl-wrap"><table>
          <thead><tr><th>时间</th><th>用户</th><th>来源 IP</th><th>操作</th><th>主机</th><th>结果</th><th>详情</th></tr></thead>
          <tbody>{rows.map((e, i) => {
            const [cls, label] = RESULT[e.result] || ['plain', e.result]
            return <tr key={i}>
              <td className="nowrap num">{new Date(e.time).toLocaleString()}</td>
              <td>{e.user || '—'}</td>
              <td className="mono">{e.ip || '—'}</td>
              <td>{ACTION_LABEL[e.action] || e.action}</td>
              <td>{e.hostName || e.host || '—'}</td>
              <td><span className={'badge ' + cls}>{label}</span></td>
              <td style={{overflowWrap: 'anywhere', maxWidth: 520}}>
                {e.error && <div className="form-err">{e.error}</div>}
                <span className="mono dim">{detailText(e)}</span>
              </td>
            </tr>
          })}</tbody>
        </table></div> : <div className="empty">{data ? '还没有记录' : '加载中…'}</div>}
        {(data?.entries.length || 0) >= limit && <div style={{padding: 8}}><button className="btn" onClick={() => setLimit(limit * 2)}>显示更多</button></div>}
      </div>
    </div>
  )
}
