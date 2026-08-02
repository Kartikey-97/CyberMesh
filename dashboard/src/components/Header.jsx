import React from 'react';

export default function Header({ mode, metrics, services, onModeChange, onTogglePolicies }) {
  const totalServices = Object.keys(services || {}).length;
  const latency = (metrics?.avg_latency_ms || 0).toFixed(2);

  return (
    <header className="hero-header compact-ribbon">
      <div className="hero-logo-group">
        <div className="hero-icon compact">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 22S4 16 4 10V5L12 2L20 5V10C20 16 12 22 12 22Z" stroke="#FFF" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M12 8V12" stroke="#FFF" strokeWidth="2.5" strokeLinecap="round"/>
            <path d="M12 16H12.01" stroke="#FFF" strokeWidth="2.5" strokeLinecap="round"/>
          </svg>
        </div>
        <div className="hero-titles">
          <h1>CyberMesh Dashboard</h1>
        </div>
      </div>

      <div className="ribbon-metrics">
        <div className="ribbon-metric">
          <span className="metric-val">{totalServices}</span>
          <span className="metric-lbl">Secured Services</span>
        </div>
        <div className="ribbon-divider"></div>
        <div className="ribbon-metric">
          <span className="metric-val">{latency}ms</span>
          <span className="metric-lbl">Security Overhead</span>
        </div>
        <div className="ribbon-divider"></div>
        <div className="ribbon-metric">
          <span className="metric-val text-green">System Healthy</span>
          <span className="metric-lbl">DPoP Identity Active</span>
        </div>
      </div>

      <div className="header-controls">
        <button 
          onClick={onTogglePolicies}
          className="btn-info"
          title="View Active Security Policies"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="16" x2="12" y2="12"></line>
            <line x1="12" y1="8" x2="12.01" y2="8"></line>
          </svg>
          <span style={{marginLeft: '6px', fontSize: '0.8rem', fontWeight: 500}}>Policies</span>
        </button>

        <div className="mode-toggle-group">
          <button 
            className={`btn-ribbon ${mode === 'learning' ? 'active' : ''}`} 
            onClick={() => onModeChange('learning')}
          >
            {mode === 'learning' && <span className="dot pulse-amber"></span>}
            Passive Observation
          </button>
          
          <button 
            className={`btn-ribbon ${mode === 'enforce' ? 'active' : ''}`} 
            onClick={() => onModeChange('enforce')}
          >
            {mode === 'enforce' && <span className="dot pulse-green"></span>}
            Active Enforcement
          </button>
        </div>
        
        {/* Hidden demo trigger */}
        <button 
          onClick={() => onModeChange('demo-replay')}
          className="btn-demo-hidden"
          title="Trigger Demo"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
          </svg>
        </button>
      </div>
    </header>
  );
}
