import React from 'react';

export default function ThreatTimeline({ events }) {
  const significantEvents = events.filter(
    e => e.decision === 'BLOCK' || e.event_type === 'service_revoked' || e.event_type === 'mode_changed'
  ).slice(0, 50);

  const getIcon = (type, decision) => {
    if (type === 'service_revoked') {
      return (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
      );
    }
    if (type === 'mode_changed') {
      return (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3B82F6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
        </svg>
      );
    }
    if (decision === 'BLOCK') {
      return (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="15" y1="9" x2="9" y2="15"></line>
          <line x1="9" y1="9" x2="15" y2="15"></line>
        </svg>
      );
    }
    return (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
    );
  };

  return (
    <div className="threat-timeline panel">
      <div className="panel-header">
        <h2 className="panel-title">Activity Timeline</h2>
      </div>
      <div className="timeline-container" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {significantEvents.map((evt, idx) => (
          <div key={evt.event_id || idx} style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
            <div style={{ marginTop: '2px' }}>{getIcon(evt.event_type, evt.decision)}</div>
            <div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {new Date(evt.timestamp).toLocaleTimeString()}
              </div>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginTop: '2px' }}>
                {evt.event_type === 'mode_changed' && `System mode updated to ${evt.mode}`}
                {evt.event_type === 'service_revoked' && `${evt.target} was revoked from mesh`}
                {evt.decision === 'BLOCK' && `Blocked ${evt.caller} accessing ${evt.target}`}
              </div>
            </div>
          </div>
        ))}
        {significantEvents.length === 0 && <div className="text-muted" style={{ padding: '20px', textAlign: 'center' }}>No significant activity</div>}
      </div>
    </div>
  );
}
