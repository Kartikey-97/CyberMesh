import React from 'react';
import './HeaderMetrics.css';

export default function HeaderMetrics({ metrics, policyCount, theme, onThemeToggle }) {
  return (
    <div className="header-metrics-bar">
      <div className="brand">
        <div className="brand-icon">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
             <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h1 className="brand-title">CyberMesh</h1>
        <div 
          className={`theme-pill-toggle ${theme}`} 
          onClick={onThemeToggle}
          title="Toggle Theme"
        >
          <div className="toggle-icon-bg left">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
          </div>
          <div className="toggle-icon-bg right">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
          </div>
          <div className="toggle-slider">
            {theme === 'light' ? (
              <svg className="slider-icon sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            ) : (
              <svg className="slider-icon moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            )}
          </div>
        </div>
      </div>

      <div className="metric-group">
        <div className="metric-item">
          <span className="metric-value">{metrics.registered_services || 3}</span>
          <span className="metric-label">Protected Services</span>
        </div>
        <div className="metric-divider"></div>
        <div className="metric-item">
          <span className="metric-value text-red">{metrics.blocked || 0}</span>
          <span className="metric-label">Blocked Threats</span>
        </div>
        <div className="metric-divider"></div>
        <div className="metric-item">
          <span className="metric-value text-green">{metrics.allowed || 0}</span>
          <span className="metric-label">Identity Validations</span>
        </div>
        <div className="metric-divider"></div>
        <div className="metric-item">
          <span className="metric-value">{metrics.avg_latency_ms || '0.00'}ms</span>
          <span className="metric-label">Security Overhead</span>
        </div>
        <div className="metric-divider"></div>
        <div className="metric-item">
          <span className="metric-value">{metrics.p95_latency_ms || '0.00'}ms</span>
          <span className="metric-label">P95 Latency</span>
        </div>
        <div className="metric-divider"></div>
        <div className="metric-item">
          <span className="metric-value">{policyCount || 0}</span>
          <span className="metric-label">Active Policies</span>
        </div>
      </div>
    </div>
  );
}
