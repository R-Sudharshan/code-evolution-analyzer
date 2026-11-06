import { NavLink, Routes, Route, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { getToken, clearToken } from "./api.js";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Targets from "./pages/Targets.jsx";
import Assessments from "./pages/Assessments.jsx";
import AssessmentDetail from "./pages/AssessmentDetail.jsx";
import Findings from "./pages/Findings.jsx";
import Reports from "./pages/Reports.jsx";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: <path d="M3 12l7-7 7 7M5 10v10h5v-6h4v6h5V10" /> },
  { to: "/targets", label: "Targets", icon: <path d="M12 3l7 4v10l-7 4-7-4V7l7-4zM12 8.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7z" /> },
  { to: "/assessments", label: "Assessments", icon: <path d="M4 19V5m0 14h16M8 15l4-4 3 3 5-6" /> },
  { to: "/findings", label: "Findings", icon: <path d="M10.3 3.9L1.8 17.4A2 2 0 003.5 20.5h17a2 2 0 001.7-3.1L13.7 3.9a2 2 0 00-3.4 0zM12 9v4M12 17h.01" /> },
  { to: "/reports", label: "Reports", icon: <path d="M7 3h7l4 4v14a1 1 0 01-1 1H7a1 1 0 01-1-1V4a1 1 0 011-1zM14 3v5h5" /> },
];

function Protected({ children }) {
  const location = useLocation();
  if (!getToken()) return <Navigate to="/login" state={{ from: location }} replace />;
  return children;
}

function Shell({ children }) {
  const navigate = useNavigate();
  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-line bg-panel/70">
        <div className="flex items-center gap-2 border-b border-line px-5 h-16">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/15 ring-1 ring-accent/40">
            <svg viewBox="0 0 24 24" className="h-5 w-5 text-accent" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3l7 3v6c0 4.4-3.1 7.6-7 9-3.9-1.4-7-4.6-7-9V6l7-3z" /></svg>
          </div>
          <div>
            <div className="text-sm font-bold tracking-wide text-slate-100">pentai</div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-muted">human-in-the-loop</div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${isActive ? "bg-accent/10 text-accent" : "text-slate-300 hover:bg-white/5 hover:text-slate-100"}`
              }
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4">{item.icon}</svg>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-line p-4 text-[10px] text-muted">
          <div className="mb-2">Authorized testing only. Every step requires your approval.</div>
          <button className="btn btn-ghost w-full justify-center !py-2" onClick={() => { clearToken(); navigate("/login"); }}>Sign out</button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto scrollbar">{children}</main>
    </div>
  );
}

export default function App() {
  const location = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route
        path="/dashboard"
        element={<Protected><Shell><Dashboard /></Shell></Protected>}
      />
      <Route
        path="/targets"
        element={<Protected><Shell><Targets /></Shell></Protected>}
      />
      <Route
        path="/assessments"
        element={<Protected><Shell><Assessments /></Shell></Protected>}
      />
      <Route
        path="/assessments/:id"
        element={<Protected><Shell><AssessmentDetail /></Shell></Protected>}
      />
      <Route
        path="/findings"
        element={<Protected><Shell><Findings /></Shell></Protected>}
      />
      <Route
        path="/reports"
        element={<Protected><Shell><Reports /></Shell></Protected>}
      />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
