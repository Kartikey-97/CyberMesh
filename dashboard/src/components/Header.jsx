import React from 'react';

export default function Header({ mode, metrics }) {
  return (
    <header className="header panel">
      <div className="logo-container">
        <h1 className="logo">
          Cyber<span>Mesh</span>
        </h1>
        <div className={`mode-indicator ${mode.toLowerCase()}`}>
          {mode.toLowerCase() === 'learning' ? (
            <span className="dot pulse-green"></span>
          ) : (
            <span className="icon lock">🔒</span>
          )}
          <span>{mode.toUpperCase()}</span>
        </div>
      </div>

      <div className="metrics-container">
        <div className="metric">
          <span className="metric-label">TOTAL REQUESTS</span>
          <span className="metric-value font-mono">{metrics?.total_requests || 0}</span>
        </div>
        <div className="metric">
          <span className="metric-label">LATENCY</span>
          <span className="metric-value font-mono">{metrics?.avg_latency_ms?.toFixed(2) || '0.00'} ms</span>
        </div>
        <div className="metric">
          <span className="metric-label">BLOCKED</span>
          <span className="metric-value font-mono text-red">{metrics?.blocked || 0}</span>
        </div>
      </div>
    </header>
  );
}
