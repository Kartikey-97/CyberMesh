import React, { useRef, useEffect } from 'react';

export default function LiveFeed({ events, onSelectEvent, selectedEventId }) {
  const feedRef = useRef(null);

  return (
    <div className="live-feed panel">
      <div className="panel-header">
        <h2 className="panel-title">Recent Security Events</h2>
        <button className="panel-action-btn">Operational Audit Log</button>
      </div>
      
      <div className="event-list" ref={feedRef}>
        {events.filter(evt => evt.event_type === 'request_decision').map((evt, idx) => {
          const isShadow = evt.shadow;
          const isRecon = evt.data && evt.data.recon_alert;
          const decision = evt.decision || 'UNKNOWN';
          const isAllowed = decision === 'ALLOW';
          
          const isSelected = selectedEventId === evt.event_id;
          
          let title = isAllowed ? 'Request allowed' : 'Unauthorized request blocked';
          let subtitle = `${evt.caller} → ${evt.target} (${evt.method} ${evt.path})`;

          if (isShadow) {
            title = `Shadow Mode: Would have been ${evt.would_have_been}`;
            subtitle = `Analysis complete for ${evt.caller}. Evaluated without blocking.`;
          }

          if (isRecon) {
            title = 'Reconnaissance Detected';
            subtitle = `Anomalous access pattern detected from ${evt.caller}.`;
          }

          let blockReason = '';
          if (!isAllowed && evt.reasons && evt.reasons.length > 0) {
            const failReason = evt.reasons.find(r => r.result === 'FAIL' || r.result === 'WARN');
            if (failReason) {
              blockReason = failReason.detail;
            }
          }

          return (
            <div 
              key={evt.event_id || idx}
              className={`event-row ${isSelected ? 'selected' : ''}`}
              onClick={() => onSelectEvent(evt)}
            >
              <div className={`event-status-bar ${isRecon ? 'bg-purple' : isAllowed ? 'bg-green' : 'bg-red'}`}></div>
              <div className="event-content" style={{ paddingLeft: '12px', width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span className={`status-badge ${isAllowed ? 'green' : 'red'}`} style={{ fontSize: '0.65rem' }}>
                    {isAllowed ? 'ALLOW' : 'BLOCK'}
                  </span>
                  <span className="event-time" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {new Date(evt.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}
                  </span>
                </div>
                
                <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontWeight: 600, marginBottom: '4px' }}>
                  {evt.caller} <span style={{ color: 'var(--text-muted)', margin: '0 4px' }}>→</span> {evt.target}
                </div>

                {blockReason && (
                   <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                     Reason: <span style={{ color: 'var(--accent-red)' }}>{blockReason}</span>
                   </div>
                )}
                {!blockReason && isAllowed && (
                   <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                     <span style={{ color: 'var(--accent-green)' }}>✓</span> Identity Verified
                   </div>
                )}
              </div>
            </div>
          );
        })}
        {events.length === 0 && <div className="text-muted" style={{ padding: '20px', textAlign: 'center' }}>Waiting for events...</div>}
      </div>
    </div>
  );
}
