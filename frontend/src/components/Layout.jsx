import React from "react";
import { NavLink, Outlet } from "react-router-dom";

const links = [
  ["/", "Dashboard"],
  ["/scan/new", "New Scan"],
  ["/history", "Scan History"],
  ["/reports", "Reports"],
  ["/settings", "Settings"],
];

export default function Layout() {
  return (
    <div className="min-h-screen flex text-slate-200">
      <aside className="w-60 bg-slate-900 border-r border-slate-800 p-4 flex flex-col justify-between">
        <div>
          <div className="mb-6">
            <div className="text-emerald-400 font-bold text-lg flex items-center gap-1.5">
              <span>🛡</span>
              <span>ZeroTrace</span>
            </div>
            <div className="text-[10px] text-slate-400 font-medium tracking-wide">Automated Web Vulnerability Scanner</div>
            <div className="text-[9px] text-emerald-500/80 italic mt-0.5">Discover. Analyze. Secure.</div>
          </div>
          <nav className="space-y-1">
            {links.map(([to, label]) => (
              <NavLink
                key={to}
                to={to}
                end={to === "/"}
                className={({ isActive }) =>
                  `block px-3 py-2 rounded text-sm transition-colors ${
                    isActive ? "bg-emerald-600/20 text-emerald-300 font-semibold" : "hover:bg-slate-800 text-slate-300"
                  }`
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
        </div>
        <p className="text-[11px] text-slate-500 mt-8">Authorized testing only. Scan systems you own or have written permission to test.</p>
      </aside>
      <main className="flex-1 p-6 overflow-auto bg-slate-950/60">
        <Outlet />
      </main>
    </div>
  );
}
