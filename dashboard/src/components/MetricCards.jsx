import React from 'react';

export default function MetricCards({ metrics, services }) {
  const totalServices = Object.keys(services || {}).length;
  
  return (
    <div className="metric-cards-grid">
      
      {/* Card 1: Identity / Authentication */}
      <div className="metric-card healthy">
        <div className="metric-card-header">
          <span className="metric-icon text-green">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
            </svg>
          </span>
          <div className="metric-badge bg-green-soft">
            <span className="dot"></span> Healthy
          </div>
        </div>
        <h3 className="metric-title">Authentication Service</h3>
        <p className="metric-desc">DPoP Identity verification is active. {totalServices} services registered.</p>
      </div>

      {/* Card 2: Policy Engine */}
      <div className="metric-card warning">
        <div className="metric-card-header">
          <span className="metric-icon text-amber">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </span>
          <div className="metric-badge bg-amber-soft">
            <span className="dot"></span> Active
          </div>
        </div>
        <h3 className="metric-title">Policy Engine</h3>
        <p className="metric-desc">Security policies are loaded successfully and enforcing rules.</p>
      </div>

      {/* Card 3: AI Engine */}
      <div className="metric-card" style={{ '--accent': 'var(--accent-blue)' }}>
        <div className="metric-card-header">
          <span className="metric-icon text-blue">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9.59 4.59A2 2 0 1 1 11 8H2m10.59 11.41A2 2 0 1 0 14 16H2m15.73-8.27A2.5 2.5 0 1 1 19.5 12H2"/>
            </svg>
          </span>
          <div className="metric-badge bg-blue-soft">
            <span className="dot"></span> Running
          </div>
        </div>
        <h3 className="metric-title">AI Detection Engine</h3>
        <p className="metric-desc">Monitoring incoming API requests for behavioral anomalies.</p>
      </div>

      {/* Card 4: Gateway / Proxy */}
      <div className="metric-card healthy">
        <div className="metric-card-header">
          <span className="metric-icon text-green">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 3h4v4h-4zM2 3h4v4H2zM2 17h4v4H2zM18 17h4v4h-4zM6 5h12M6 19h12M5 7v10M19 7v10M12 12v.01"/>
            </svg>
          </span>
          <div className="metric-badge bg-green-soft">
            <span className="dot"></span> Connected
          </div>
        </div>
        <h3 className="metric-title">API Gateway</h3>
        <p className="metric-desc">Forwarding verified requests securely with {(metrics?.avg_latency_ms || 0).toFixed(2)}ms avg latency.</p>
      </div>

    </div>
  );
}
