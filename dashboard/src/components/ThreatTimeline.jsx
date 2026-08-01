import React from 'react';

export default function ThreatTimeline({ events }) {
  const significantEvents = events.filter(
    e => e.decision === 'BLOCK' || e.event_type === 'service_revoked' || e.event_type === 'mode_changed'
  ).slice(0, 50);

  const getIcon = (type, decision) => {
    if (type === 'service_revoked') return '🔑';
    if (type === 'mode_changed') return '👁️';
    if (decision === 'BLOCK') return '🛡️';
    return '⚡';
  };

  return (
    <div className="threat-timeline panel">
      <h2>Activity Timeline</h2>
      <div className="timeline-container">
        {significantEvents.map(evt => (
          <div key={evt.event_id} className={`timeline-item animate-slide-in`}>
            <div className="timeline-icon">{getIcon(evt.event_type, evt.decision)}</div>
            <div className="timeline-content">
              <div className="timeline-time font-mono">{new Date(evt.timestamp).toLocaleTimeString()}</div>
              <div className="timeline-desc">
                {evt.event_type === 'mode_changed' && `Mode changed to ${evt.mode}`}
                {evt.event_type === 'service_revoked' && `${evt.target} was revoked`}
                {evt.decision === 'BLOCK' && `Blocked ${evt.caller} accessing ${evt.target}`}
              </div>
            </div>
          </div>
        ))}
        {significantEvents.length === 0 && <div className="empty-state text-muted">No significant activity</div>}
      </div>
    </div>
  );
}
