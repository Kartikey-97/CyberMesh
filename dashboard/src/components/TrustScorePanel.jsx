import React from 'react';

export default function TrustScorePanel({ event }) {
  if (!event) return null;

  const score = event.trust_score || 0;
  let color = 'var(--accent-green)'; 
  let circleClass = 'high';
  if (score < 40) {
    color = 'var(--accent-red)'; 
    circleClass = 'low';
  } else if (score < 70) {
    color = 'var(--accent-amber)';
    circleClass = 'medium';
  }

  const hasDecay = event.data && event.data.decay_applied > 0;
  const rawBehavior = hasDecay ? event.data.behavior_score_raw : event.behavior_score;

  return (
    <div className="panel trust-score-panel">
      <div className="panel-header">
        <h2 className="panel-title">Zero-Trust Threat Analysis</h2>
      </div>
      
      <div className="trust-score-header">
        <div className={`score-circle ${circleClass}`}>
          {score.toFixed(0)}
        </div>
        <div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>Dynamic Trust Score</div>
          <div className="metric-title" style={{ color }}>{event.band?.toUpperCase() || 'UNKNOWN'}</div>
        </div>
      </div>

      <div className="reason-list">
        <div className={`reason-item ${event.identity_score === 100 ? 'pass' : 'fail'}`}>
          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            {event.identity_score === 100 ? '[PASS]' : '[FAIL]'}
          </span>
          <div style={{ marginLeft: '8px' }}>
            <strong>Identity ({event.identity_score?.toFixed(0)})</strong> <br/>
            <span style={{ color: 'var(--text-secondary)' }}>
              {event.identity_score === 100 ? "DPoP signature & JTI verified" : "Authentication or replay failure"}
            </span>
          </div>
        </div>
        
        <div className={`reason-item ${event.behavior_score > 70 ? 'pass' : event.behavior_score > 40 ? 'warn' : 'fail'}`}>
          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
             {event.behavior_score > 70 ? '[PASS]' : event.behavior_score > 40 ? '[WARN]' : '[FAIL]'}
          </span>
          <div style={{ marginLeft: '8px' }}>
            <strong>Behavior ({event.behavior_score?.toFixed(0)})</strong> <br/>
            <span style={{ color: 'var(--text-secondary)' }}>
              {hasDecay ? `Trust drift applied (was ${rawBehavior?.toFixed(0)})` : "Historical patterns analyzed"}
            </span>
          </div>
        </div>
        
        <div className={`reason-item ${event.context_score > 70 ? 'pass' : 'fail'}`}>
          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
             {event.context_score > 70 ? '[PASS]' : '[FAIL]'}
          </span>
          <div style={{ marginLeft: '8px' }}>
            <strong>Context ({event.context_score?.toFixed(0)})</strong> <br/>
            <span style={{ color: 'var(--text-secondary)' }}>
              {event.context_score === 100 ? "Payload and IP verified" : "Anomalous context detected"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
