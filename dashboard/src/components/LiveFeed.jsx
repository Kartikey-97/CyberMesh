import React, { useRef, useState, useEffect } from 'react';

export default function LiveFeed({ events, onSelectEvent, selectedEventId }) {
  const feedRef = useRef(null);
  const [isPaused, setIsPaused] = useState(false);
  const [snapshot, setSnapshot] = useState([]);

  // When paused, save the current events
  useEffect(() => {
    if (isPaused) {
      setSnapshot(events);
    }
  }, [isPaused]);

  const displayEvents = isPaused ? snapshot : events;

  return (
    <div className="live-feed panel">
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 className="panel-title">Recent Security Events</h2>
        <button 
          onClick={() => setIsPaused(!isPaused)}
          style={{
            background: isPaused ? 'rgba(239, 68, 68, 0.1)' : 'transparent',
            border: `1px solid ${isPaused ? 'rgba(239, 68, 68, 0.3)' : 'var(--border-subtle)'}`,
            color: isPaused ? 'var(--accent-red)' : 'var(--text-muted)',
            cursor: 'pointer',
            padding: '4px 8px',
            borderRadius: '4px',
            fontSize: '0.75rem',
            transition: 'all 0.2s'
          }}
        >
          {isPaused ? '▶ Resume Feed' : '⏸ Pause Feed'}
        </button>
      </div>
      
      <div className="event-list" ref={feedRef}>
        {displayEvents.filter(evt => evt.event_type === 'request_decision').map((evt, idx) => {
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

          const isBlock = !isAllowed;
          const isLateral = isBlock && blockReason.includes('Lateral Movement');
          const isReplay = isBlock && blockReason.includes('Replay Detected');

          // Styling variables
          let borderColor = 'transparent';
          let bgColor = 'transparent';
          let badgeColor = 'gray';
          let badgeText = isAllowed ? 'ALLOW' : 'BLOCK';

          if (isAllowed) {
            borderColor = 'rgba(16, 185, 129, 0.3)';
            bgColor = 'var(--bg-green-faint, rgba(16, 185, 129, 0.05))';
            badgeColor = 'green';
          } else if (isReplay) {
            borderColor = 'rgba(249, 115, 22, 0.3)';
            bgColor = 'var(--bg-orange-faint, rgba(249, 115, 22, 0.05))';
            badgeColor = 'orange';
            badgeText = 'REPLAY';
          } else if (isLateral) {
            borderColor = 'rgba(239, 68, 68, 0.3)';
            bgColor = 'var(--bg-red-faint, rgba(239, 68, 68, 0.05))';
            badgeColor = 'red';
            badgeText = 'LATERAL';
          } else if (isBlock) {
            borderColor = 'rgba(239, 68, 68, 0.3)';
            bgColor = 'var(--bg-red-faint, rgba(239, 68, 68, 0.05))';
            badgeColor = 'red';
          }

          return (
            <div 
              key={evt.event_id || idx}
              className={`event-row ${isSelected ? 'selected' : ''}`}
              onClick={() => onSelectEvent(evt)}
              style={{
                border: `1px solid ${borderColor}`,
                backgroundColor: isSelected ? 'var(--bg-hover)' : bgColor,
                marginBottom: '8px',
                borderRadius: '6px',
                transition: 'all 0.2s ease',
              }}
            >
              <div className={`event-status-bar ${isRecon ? 'bg-purple' : isAllowed ? 'bg-green' : 'bg-red'}`} style={{ borderTopLeftRadius: '6px', borderBottomLeftRadius: '6px' }}></div>
              <div className="event-content" style={{ paddingLeft: '12px', paddingRight: '8px', paddingBottom: '8px', width: '100%' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span className={`status-badge ${badgeColor}`} style={{ fontSize: '0.65rem' }}>
                    {badgeText}
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
        {displayEvents.length === 0 && <div className="text-muted" style={{ padding: '20px', textAlign: 'center' }}>Waiting for events...</div>}
      </div>
    </div>
  );
}
