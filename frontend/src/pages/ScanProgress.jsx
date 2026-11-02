import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { getScan, cancelScan } from "../services/api";
import usePolling from "../hooks/usePolling";
import { Card, Spinner } from "../components/ui";

const done = (s) => ["completed", "failed", "cancelled"].includes(s?.status);

const MODULE_TITLES = {
  crawler: "Discovering website pages & mapping attack surface",
  sql_injection: "Testing for SQL Injection (Error, Boolean & Time-based)",
  xss: "Auditing Cross-Site Scripting (Reflected & DOM XSS)",
  csrf: "Checking Cross-Site Request Forgery (CSRF) protections",
  security_headers: "Evaluating HTTP security headers & policies",
  cookie_security: "Analyzing cookie security flags (HttpOnly, Secure, SameSite)",
  directory_listing: "Probing directory listing & path exposures",
  sensitive_files: "Scanning for sensitive files, backups & credentials",
  open_redirect: "Testing open URL redirection vulnerabilities",
  information_disclosure: "Analyzing technical error disclosures & stack traces",
  command_injection: "Testing Remote Command Injection vulnerabilities",
  ssti: "Auditing Server-Side Template Injection (SSTI)",
  path_traversal: "Testing directory & path traversal vulnerabilities",
  cors: "Evaluating Cross-Origin Resource Sharing (CORS) rules",
  clickjacking: "Auditing X-Frame-Options & clickjacking defenses",
  auth_security: "Testing authentication & route access controls",
  graphql: "Inspecting GraphQL endpoints & introspection",
  reporting: "Generating scan report & executive security posture",
  summary: "Generating scan report & executive security posture",
  posture: "Generating scan report & executive security posture",
};

export default function ScanProgress() {
  const { id } = useParams();
  const { data: s } = usePolling(() => getScan(id), [id], 1000, done);
  const [cancelling, setCancelling] = useState(false);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [displayPercent, setDisplayPercent] = useState(0);

  // Compute live elapsed duration
  useEffect(() => {
    if (!s?.started_at) return;
    const startMs = new Date(s.started_at).getTime();

    const updateElapsed = () => {
      const endMs = s.completed_at ? new Date(s.completed_at).getTime() : Date.now();
      setElapsedSeconds(Math.max(0, Math.floor((endMs - startMs) / 1000)));
    };

    updateElapsed();
    if (s.status === "running" || s.status === "pending") {
      const interval = setInterval(updateElapsed, 1000);
      return () => clearInterval(interval);
    }
  }, [s?.started_at, s?.completed_at, s?.status]);

  // Animate progress percentage changes smoothly without faking numbers
  useEffect(() => {
    if (!s) return;
    const target = Math.min(100, Math.max(0, Math.round(s.progress_percent || 0)));

    if (target === 0) {
      setDisplayPercent(0);
      return;
    }

    let startTimestamp = null;
    const startValue = displayPercent;
    const delta = target - startValue;
    if (delta === 0) return;

    let frameId;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / 500, 1);
      // easeOutCubic
      const factor = 1 - Math.pow(1 - progress, 3);
      setDisplayPercent(Math.round(startValue + delta * factor));
      if (progress < 1) {
        frameId = requestAnimationFrame(step);
      }
    };
    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [s?.progress_percent]);

  if (!s) return <Spinner message="Connecting to ZeroTrace scanner engine..." />;

  const isRunning = s.status === "running";
  const isCompleted = s.status === "completed";
  const isFailed = s.status === "failed";
  const isCancelled = s.status === "cancelled";
  const isPending = s.status === "pending";

  const handleCancel = async () => {
    if (window.confirm("Are you sure you want to stop this scan? Partial results will be preserved.")) {
      setCancelling(true);
      try {
        await cancelScan(id);
      } catch (err) {
        console.error("Cancel scan failed:", err);
      } finally {
        setCancelling(false);
      }
    }
  };

  // Format elapsed time as mm:ss
  const formatDuration = (sec) => {
    const mins = Math.floor(sec / 60);
    const remainder = sec % 60;
    return `${mins.toString().padStart(2, "0")}:${remainder.toString().padStart(2, "0")}`;
  };

  const formsCount = s.route_summary?.forms_discovered ?? 0;

  // Determine dynamic phase category and theme colors
  const getPhaseInfo = () => {
    if (isFailed) {
      return {
        phase: "SCAN FAILED",
        color: "rose",
        accentHex: "#f43f5e",
        badgeBg: "bg-rose-950/80 border-rose-500/50 text-rose-300",
        radarGradient: "rgba(244, 63, 94, 0.4)",
        glowClass: "shadow-[0_0_25px_rgba(244,63,94,0.35)]",
      };
    }
    if (isCancelled) {
      return {
        phase: "SCAN CANCELLED",
        color: "amber",
        accentHex: "#f59e0b",
        badgeBg: "bg-amber-950/60 border-amber-500/40 text-amber-300",
        radarGradient: "rgba(245, 158, 11, 0.3)",
        glowClass: "shadow-[0_0_20px_rgba(245,158,11,0.2)]",
      };
    }
    if (isCompleted) {
      return {
        phase: "ASSESSMENT COMPLETE",
        color: "emerald",
        accentHex: "#10b981",
        badgeBg: "bg-emerald-950/80 border-emerald-500/60 text-emerald-300",
        radarGradient: "rgba(16, 185, 129, 0.4)",
        glowClass: "shadow-[0_0_25px_rgba(16,185,129,0.35)]",
      };
    }
    if (isPending) {
      return {
        phase: "INITIALIZING",
        color: "sky",
        accentHex: "#0ea5e9",
        badgeBg: "bg-sky-950/70 border-sky-500/50 text-sky-300",
        radarGradient: "rgba(14, 165, 233, 0.3)",
        glowClass: "shadow-[0_0_20px_rgba(14,165,233,0.25)]",
      };
    }

    const mod = s.current_module || "";

    // 1. Blue for Discovery
    if (mod === "crawler" || (s.urls_discovered > 0 && s.urls_scanned === 0)) {
      return {
        phase: "DISCOVERY PHASE",
        color: "sky",
        accentHex: "#0ea5e9",
        badgeBg: "bg-sky-950/80 border-sky-500/50 text-sky-300",
        radarGradient: "rgba(14, 165, 233, 0.5)",
        glowClass: "shadow-[0_0_25px_rgba(14,165,233,0.35)]",
      };
    }

    // 2. Orange for Analysis
    if (
      [
        "cookie_security",
        "information_disclosure",
        "cors",
        "clickjacking",
        "reporting",
        "summary",
        "posture",
      ].includes(mod)
    ) {
      return {
        phase: "SECURITY ANALYSIS",
        color: "amber",
        accentHex: "#f59e0b",
        badgeBg: "bg-amber-950/80 border-amber-500/50 text-amber-300",
        radarGradient: "rgba(245, 158, 11, 0.5)",
        glowClass: "shadow-[0_0_25px_rgba(245,158,11,0.35)]",
      };
    }

    // 3. Green for Active Scanning (SQLi, XSS, headers, command injection, etc.)
    return {
      phase: "ACTIVE SCANNING",
      color: "emerald",
      accentHex: "#10b981",
      badgeBg: "bg-emerald-950/80 border-emerald-500/50 text-emerald-300",
      radarGradient: "rgba(16, 185, 129, 0.55)",
      glowClass: "shadow-[0_0_25px_rgba(16,185,129,0.35)]",
    };
  };

  const phaseInfo = getPhaseInfo();

  // Determine dynamic scanner activity message based on actual backend module & telemetry
  const getActivityMessage = () => {
    if (isPending) return "Initializing scanner...";
    if (isCompleted) return "Scan completed successfully. Security posture and reports generated.";
    if (isFailed) return s.error_message ? `Scan failed: ${s.error_message}` : "Scan execution encountered an error.";
    if (isCancelled) return "Scan was cancelled by user. Partial results preserved.";

    const mod = s.current_module;
    if (mod === "crawler") {
      if (formsCount > 0) return "Analyzing forms and inputs...";
      if ((s.urls_discovered || 0) > 0) return "Discovering website pages...";
      return "Discovering website pages...";
    }
    if (mod === "sql_injection") return "Testing SQL Injection...";
    if (mod === "xss") return "Testing Cross-Site Scripting...";
    if (mod === "security_headers") return "Checking security headers...";
    if (mod === "csrf") return "Checking Cross-Site Request Forgery (CSRF)...";
    if (mod === "cookie_security") return "Auditing cookie security & flags...";
    if (mod === "sensitive_files") return "Scanning for sensitive files & secrets...";
    if (mod === "command_injection") return "Testing Command Injection...";
    if (mod === "ssti") return "Auditing Server-Side Template Injection (SSTI)...";
    if (mod === "path_traversal") return "Testing directory & path traversal...";
    if (mod === "cors") return "Evaluating Cross-Origin Resource Sharing (CORS)...";
    if (mod === "clickjacking") return "Auditing clickjacking defenses...";
    if (mod === "auth_security") return "Testing authentication & route access controls...";
    if (mod === "directory_listing") return "Probing directory listing & exposures...";
    if (mod === "information_disclosure") return "Analyzing technical disclosures & stack traces...";
    if (mod === "graphql") return "Auditing GraphQL schema & introspection...";
    if (mod === "reporting" || mod === "summary" || mod === "posture") return "Generating scan report...";

    if ((s.urls_scanned || 0) > 0 || (s.parameters_found || 0) > 0) {
      return "Analyzing vulnerabilities...";
    }
    if ((s.urls_discovered || 0) > 0) {
      return "Discovering website pages...";
    }
    return "Initializing scanner...";
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12">
      {/* Top Header & Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1">
            <Link to="/history" className="hover:text-emerald-400 transition-colors">Scans</Link>
            <span>/</span>
            <span className="text-slate-200 truncate max-w-xs">{id}</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Scan Execution & Assessment</span>
          </h1>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            <span>Target:</span>
            <span className="font-mono text-slate-200 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              {s.target?.base_url || "Target URL"}
            </span>
            {s.application?.name && (
              <span className="text-xs text-slate-400">
                (App: <b className="text-slate-300">{s.application.name}</b>)
              </span>
            )}
          </div>
        </div>

        {/* Dynamic Status Badge */}
        <div className="flex items-center gap-3">
          {isRunning && (
            <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-emerald-950/80 border border-emerald-500/50 text-emerald-400 text-xs font-semibold tracking-wide shadow-[0_0_18px_rgba(16,185,129,0.35)] animate-pulse-glow">
              {/* Animated glowing green indicator */}
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400 shadow-[0_0_8px_#10b981]"></span>
              </span>

              {/* Animated scanning radar reticle icon */}
              <svg className="w-3.5 h-3.5 text-emerald-400 animate-spin" style={{ animationDuration: "3.5s" }} viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <circle cx="12" cy="12" r="9" strokeWidth="1.75" strokeDasharray="5 5" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 7v5l3 2" />
              </svg>

              <span className="font-mono font-bold tracking-wider">RUNNING</span>
            </div>
          )}

          {isCompleted && (
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-emerald-950/70 border border-emerald-500/60 text-emerald-300 text-xs font-semibold tracking-wide shadow-[0_0_15px_rgba(16,185,129,0.25)]">
              <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
              </svg>
              <span className="font-mono font-bold tracking-wider">COMPLETED</span>
            </div>
          )}

          {isFailed && (
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-rose-950/80 border border-rose-500/50 text-rose-300 text-xs font-semibold tracking-wide shadow-[0_0_15px_rgba(244,63,94,0.3)]">
              <svg className="w-4 h-4 text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span className="font-mono font-bold tracking-wider">FAILED</span>
            </div>
          )}

          {isCancelled && (
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-slate-900 border border-slate-700 text-slate-300 text-xs font-semibold tracking-wide">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-400"></span>
              <span className="font-mono font-bold tracking-wider">CANCELLED</span>
            </div>
          )}

          {isPending && (
            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-sky-950/60 border border-sky-500/40 text-sky-300 text-xs font-semibold tracking-wide">
              <span className="animate-spin h-3 w-3 border-2 border-sky-400 border-t-transparent rounded-full"></span>
              <span className="font-mono font-bold tracking-wider">INITIALIZING</span>
            </div>
          )}

          <div className="text-xs font-mono text-slate-400 bg-slate-900/80 border border-slate-800 px-3 py-1.5 rounded-lg">
            ⏱ {formatDuration(elapsedSeconds)}
          </div>
        </div>
      </div>

      {/* Main Cybersecurity Scanning Animation Hero Card */}
      <Card className="relative overflow-hidden border-slate-800/90 bg-gradient-to-b from-slate-900/95 via-slate-900/85 to-slate-950/95 p-6 sm:p-8">
        {/* Subtle Background Grid Pattern */}
        <div
          className="absolute inset-0 opacity-[0.035] pointer-events-none"
          style={{
            backgroundImage: "radial-gradient(#38bdf8 1px, transparent 1px)",
            backgroundSize: "24px 24px",
          }}
        />

        <div className="flex flex-col items-center justify-center text-center relative z-10 py-3">
          {/* Cyber Radar / Shield Animation Viewport */}
          <div className="relative w-52 h-52 mb-6 flex items-center justify-center">
            {/* Concentric Radar Rings */}
            <div className="absolute inset-0 rounded-full border border-slate-800/90" />
            <div className="absolute inset-6 rounded-full border border-slate-800/60" />
            <div className="absolute inset-12 rounded-full border border-slate-800/40" />
            <div className="absolute inset-16 rounded-full border border-slate-800/25" />

            {/* Radar Crosshairs */}
            <div className="absolute inset-x-0 top-1/2 h-[1px] bg-slate-800/40 -translate-y-1/2" />
            <div className="absolute inset-y-0 left-1/2 w-[1px] bg-slate-800/40 -translate-x-1/2" />

            {/* Subtle horizontal scanning grid lines in radar background */}
            <div className="absolute inset-0 opacity-[0.06] pointer-events-none overflow-hidden rounded-full">
              <div className="w-full h-full bg-[repeating-linear-gradient(0deg,transparent,transparent_6px,rgba(255,255,255,0.4)_7px,transparent_8px)]" />
            </div>

            {/* When Running: Radar Waves, Sweeping Beam & Orbiting Particles */}
            {isRunning && (
              <>
                {/* Concentric Expanding Sonar Pulse Waves */}
                <div
                  className="absolute inset-4 rounded-full border animate-radar-pulse pointer-events-none"
                  style={{ borderColor: `${phaseInfo.accentHex}88` }}
                />
                <div
                  className="absolute inset-4 rounded-full border animate-radar-pulse-delayed pointer-events-none"
                  style={{ borderColor: `${phaseInfo.accentHex}66` }}
                />

                {/* Outer Rotating Calibration Tech Ring */}
                <svg className="absolute inset-0 w-full h-full animate-ring-rotate opacity-50 pointer-events-none" viewBox="0 0 100 100">
                  <circle
                    cx="50" cy="50" r="48"
                    fill="none"
                    stroke={phaseInfo.accentHex}
                    strokeWidth="1.2"
                    strokeDasharray="4 8 2 12"
                  />
                  {/* Orbiting particles around the outer ring */}
                  <circle cx="50" cy="2" r="2" fill={phaseInfo.accentHex} className="animate-pulse" />
                  <circle cx="98" cy="50" r="1.5" fill={phaseInfo.accentHex} opacity="0.8" />
                  <circle cx="50" cy="98" r="2" fill={phaseInfo.accentHex} className="animate-pulse" />
                  <circle cx="2" cy="50" r="1.5" fill={phaseInfo.accentHex} opacity="0.8" />
                </svg>

                {/* Reverse Rotating Inner Ring */}
                <svg className="absolute inset-3 w-[calc(100%-24px)] h-[calc(100%-24px)] animate-ring-reverse opacity-30 pointer-events-none" viewBox="0 0 100 100">
                  <circle
                    cx="50" cy="50" r="46"
                    fill="none"
                    stroke="#0ea5e9"
                    strokeWidth="1"
                    strokeDasharray="8 6 4 10"
                  />
                </svg>

                {/* Rotating Conic Radar Sweep Beam */}
                <div
                  className="absolute inset-1 rounded-full animate-radar-sweep pointer-events-none opacity-75"
                  style={{
                    background: `conic-gradient(from 0deg, transparent 0deg, transparent 270deg, ${phaseInfo.radarGradient} 330deg, ${phaseInfo.accentHex} 360deg)`,
                  }}
                />
              </>
            )}

            {/* Center Core Shield / Badge */}
            <div
              className={`relative z-20 w-24 h-24 rounded-2xl flex items-center justify-center border transition-all duration-500 overflow-hidden ${
                isRunning
                  ? `bg-slate-900/95 border-emerald-500/60 ${phaseInfo.glowClass} animate-pulse-glow`
                  : isCompleted
                  ? "bg-emerald-950/70 border-emerald-500/80 shadow-[0_0_25px_rgba(16,185,129,0.3)]"
                  : isFailed
                  ? "bg-rose-950/70 border-rose-500/80 shadow-[0_0_25px_rgba(244,63,94,0.3)]"
                  : "bg-slate-900 border-slate-700"
              }`}
            >
              {/* Vertical Laser Scan Beam across shield (when running) */}
              {isRunning && (
                <div
                  className="absolute inset-x-0 h-1 pointer-events-none z-30 animate-scan-laser"
                  style={{
                    background: `linear-gradient(90deg, transparent, ${phaseInfo.accentHex}, transparent)`,
                    boxShadow: `0 0 8px ${phaseInfo.accentHex}`,
                  }}
                />
              )}

              {/* Status Specific Center Icon */}
              {isRunning && (
                <svg
                  className="w-12 h-12 transition-colors duration-500"
                  style={{
                    color: phaseInfo.accentHex,
                    filter: `drop-shadow(0 0 8px ${phaseInfo.accentHex}99)`,
                  }}
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25 5.25-1.1 9-6 9-11.25V6l-9-4z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v8M8 12h8" strokeWidth="1.5" className="opacity-60" />
                </svg>
              )}

              {isCompleted && (
                <svg className="w-12 h-12 text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              )}

              {isFailed && (
                <svg className="w-12 h-12 text-rose-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              )}

              {isCancelled && (
                <svg className="w-12 h-12 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              )}

              {isPending && (
                <svg className="w-12 h-12 text-sky-400 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" strokeDasharray="30" strokeDashoffset="10" />
                </svg>
              )}
            </div>
          </div>

          {/* Current Dynamic Activity Statement with Phase Classification */}
          <div className="max-w-xl mx-auto mb-5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-medium mb-2.5 transition-colors duration-300">
              <span
                className={`w-2 h-2 rounded-full ${
                  isRunning ? "animate-pulse" : ""
                }`}
                style={{ backgroundColor: phaseInfo.accentHex }}
              />
              <span className="font-mono uppercase tracking-wider text-[11px] text-slate-300">
                {phaseInfo.phase}
              </span>
              <span className="text-slate-500">•</span>
              <span className="text-slate-300 font-mono text-[11px]">
                {s.current_module ? `Module: ${s.current_module}` : "Engine: Core"}
              </span>
            </div>

            <h2 className="text-xl font-semibold text-slate-100 tracking-tight transition-all">
              {getActivityMessage()}
            </h2>

            {s.error_message && (
              <p className="text-rose-400 text-xs mt-2.5 font-mono bg-rose-950/40 border border-rose-900/60 p-2.5 rounded-lg max-w-lg mx-auto">
                {s.error_message}
              </p>
            )}
          </div>

          {/* Smooth Shimmer Progress Bar */}
          <div className="w-full max-w-2xl px-2">
            <div className="flex justify-between items-center text-xs font-mono mb-2">
              <span className="text-slate-400">
                {isRunning ? (
                  <span className="flex items-center gap-2 text-emerald-400 font-sans font-medium">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                    <span>Live security assessment active</span>
                  </span>
                ) : isCompleted ? (
                  <span className="text-emerald-400 font-sans font-medium flex items-center gap-1.5">
                    <span>✓</span> 100% Assessment Complete
                  </span>
                ) : isFailed ? (
                  <span className="text-rose-400 font-sans font-medium">Execution Halted</span>
                ) : isCancelled ? (
                  <span className="text-amber-400 font-sans font-medium">Assessment Cancelled</span>
                ) : (
                  <span className="text-slate-400">Progress</span>
                )}
              </span>
              <span className="text-lg font-bold font-mono text-slate-100 transition-all duration-300">
                {displayPercent}%
              </span>
            </div>

            {/* Outer Progress Track */}
            <div className="h-4 bg-slate-950/95 border border-slate-800 rounded-full overflow-hidden p-0.5 relative shadow-inner">
              {/* Indeterminate live activity pulse when progress is 0% and running */}
              {isRunning && displayPercent === 0 && (
                <div className="absolute inset-y-0 w-24 bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent rounded-full animate-track-pulse pointer-events-none" />
              )}

              {/* Inner Animated Progress Fill */}
              <div
                className={`h-full rounded-full transition-all duration-500 ease-out relative overflow-hidden ${
                  isFailed
                    ? "bg-rose-600"
                    : isCancelled
                    ? "bg-amber-600"
                    : isCompleted
                    ? "bg-emerald-500"
                    : isRunning
                    ? phaseInfo.color === "sky"
                      ? "bg-sky-500 shadow-[0_0_12px_rgba(14,165,233,0.5)]"
                      : phaseInfo.color === "amber"
                      ? "bg-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]"
                      : "bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.5)]"
                    : "bg-emerald-600"
                }`}
                style={{ width: `${displayPercent}%` }}
              >
                {/* Moving Shimmer Effect inside progress fill when running */}
                {isRunning && displayPercent > 0 && (
                  <div className="progress-shimmer-overlay pointer-events-none" />
                )}

                {/* Glowing Leading Edge Dot when running */}
                {isRunning && displayPercent > 3 && (
                  <div className="absolute right-0.5 top-1/2 -translate-y-1/2 w-2 h-2 rounded-full bg-white shadow-[0_0_8px_#ffffff]" />
                )}
              </div>
            </div>

            <div className="flex justify-between text-[11px] text-slate-500 mt-2 px-1">
              <span>
                Status: <b className="uppercase text-slate-300 font-mono">{s.status}</b>
              </span>
              <span>
                Findings Flagged: <b className="text-slate-300 font-mono">{s.findings_count ?? 0}</b>
              </span>
            </div>
          </div>
        </div>
      </Card>

      {/* Real-time Telemetry Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
            <span>URLs Discovered</span>
            <span className="text-sky-400">🌐</span>
          </div>
          <div className="text-2xl font-bold font-mono text-sky-400 tracking-tight">
            {s.urls_discovered ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {formsCount > 0 ? `${formsCount} form(s) found` : "Crawled surface"}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
            <span>Endpoints Scanned</span>
            <span className="text-emerald-400">🎯</span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tracking-tight">
            {s.urls_scanned ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Tested endpoints
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
            <span>Parameters Tested</span>
            <span className="text-amber-400">⚡</span>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 tracking-tight">
            {s.parameters_found ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            GET / POST / JSON inputs
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">
            <span>Vulnerabilities</span>
            <span className="text-rose-400">🛡</span>
          </div>
          <div className={`text-2xl font-bold font-mono tracking-tight ${s.findings_count > 0 ? "text-rose-400" : "text-slate-100"}`}>
            {s.findings_count ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {s.findings_count > 0 ? "Issues flagged" : "Clean so far"}
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
        <div className="text-xs text-slate-500">
          {!done(s) ? (
            <span>Testing target within authorized defensive parameters. Telemetry updates in real-time.</span>
          ) : isCompleted ? (
            <span className="text-emerald-400/90 flex items-center gap-1.5 font-medium">
              <span>✓</span> Security assessment finished. Full report and posture analysis are ready to review.
            </span>
          ) : isCancelled ? (
            <span className="text-amber-400/90">Assessment cancelled. Existing findings and evidence are preserved.</span>
          ) : (
            <span className="text-rose-400/90">Assessment halted due to error. Partial results preserved.</span>
          )}
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
          {!done(s) && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="w-full sm:w-auto px-4 py-2 rounded-lg text-sm font-medium bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/60 text-rose-300 disabled:opacity-50 transition-colors shadow-sm flex items-center justify-center gap-2"
            >
              {cancelling && <span className="animate-spin h-3.5 w-3.5 border-2 border-rose-400 border-t-transparent rounded-full" />}
              <span>{cancelling ? "Cancelling..." : "Cancel Scan"}</span>
            </button>
          )}

          {isCompleted && (
            <Link
              to={`/scan/${id}`}
              className="w-full sm:w-auto px-5 py-2.5 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-950/50 flex items-center justify-center gap-2 transition-all transform active:scale-95"
            >
              <span>View Scan Results</span>
              <span>→</span>
            </Link>
          )}

          <Link
            to="/dashboard"
            className="w-full sm:w-auto px-4 py-2 rounded-lg text-sm text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-800 transition-colors text-center"
          >
            Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
