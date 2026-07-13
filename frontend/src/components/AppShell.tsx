import {
  BellRing,
  BookOpenText,
  Bot,
  ChevronRight,
  CirclePlus,
  LayoutDashboard,
  LockKeyhole,
  Settings2,
  ShieldCheck,
} from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAdminAuth } from "../context/AdminAuthContext";

const navigation = [
  { to: "/", label: "态势总览", icon: LayoutDashboard, end: true },
  { to: "/alerts", label: "告警中心", icon: BellRing },
  { to: "/alerts/new", label: "发起测试", icon: CirclePlus },
  { to: "/runbooks", label: "处置手册", icon: BookOpenText, admin: true },
  { to: "/settings", label: "Agent 设置", icon: Settings2, admin: true },
];

const pageNames: Array<[RegExp, string]> = [
  [/^\/$/, "态势总览"],
  [/^\/alerts\/new$/, "发起测试告警"],
  [/^\/alerts\/[^/]+$/, "告警分析详情"],
  [/^\/alerts$/, "告警中心"],
  [/^\/runbooks$/, "处置手册"],
  [/^\/settings$/, "Agent 设置"],
];

export function AppShell() {
  const location = useLocation();
  const { unlocked } = useAdminAuth();
  const pageName = pageNames.find(([pattern]) => pattern.test(location.pathname))?.[1] || "控制台";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <NavLink to="/" className="brand" aria-label="DB Sentinel 首页">
          <span className="brand-mark">
            <Bot size={23} />
            <span className="brand-pulse" />
          </span>
          <span>
            <strong>DB Sentinel</strong>
            <small>AI 告警排查中枢</small>
          </span>
        </NavLink>

        <nav className="primary-nav" aria-label="主要导航">
          <p className="nav-caption">工作台</p>
          {navigation.map(({ to, label, icon: Icon, admin, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <Icon size={19} />
              <span>{label}</span>
              {admin && <LockKeyhole className="nav-admin-icon" size={13} aria-label="管理员功能" />}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="guardrail-card">
            <ShieldCheck size={20} />
            <div>
              <strong>安全护栏已启用</strong>
              <span>仅生成建议，不执行数据库操作</span>
            </div>
          </div>
          <div className={`admin-session ${unlocked ? "unlocked" : ""}`}>
            <span className="session-dot" />
            {unlocked ? "管理员会话已解锁" : "普通只读会话"}
          </div>
        </div>
      </aside>

      <main className="main-panel">
        <div className="topbar">
          <div className="breadcrumb">
            <span>DB Sentinel</span>
            <ChevronRight size={14} />
            <strong>{pageName}</strong>
          </div>
          <div className="topbar-signal">
            <span className="live-dot" />
            实时排查视图
          </div>
        </div>
        <div className="page-content">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
