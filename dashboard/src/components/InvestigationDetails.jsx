import React from 'react';
import './InvestigationDetails.css';

export default function InvestigationDetails({ event, onClear }) {
  if (!event) {
    return (
      <div className="panel investigation-details" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <div className="panel-header">
          <h2 className="panel-title">Investigation Details</h2>
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', color: 'var(--text-muted)' }}>
          <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ marginBottom: '12px', opacity: 0.5 }}>
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          <div style={{ fontSize: '0.9rem' }}>Select an event to investigate</div>
        </div>
      </div>
    );
  }

  const isBlocked = event.decision === 'BLOCK';
  const actionColor = isBlocked ? 'var(--accent-red)' : 'var(--accent-green)';
  const identityVerified = event.identity_score > 50;

  // Determine primary reason
  let primaryReason = 'Normal Traffic';
  let policyName = 'ALLOW_DEFAULT';
  
  if (isBlocked) {
    if (event.reasons) {
      const failingReason = event.reasons.find(r => r.result === 'FAIL' || r.result === 'WARN');
      if (failingReason) {
        primaryReason = failingReason.detail;
        if (failingReason.check === 'identity' || failingReason.check === 'pop') {
          policyName = 'ZERO_TRUST_IDENTITY';
        } else if (failingReason.check === 'policy') {
          policyName = `DENY_${event.caller.toUpperCase()}_TO_${event.target.toUpperCase()}`;
        }
      }
    }
  }

  return (
    <div className="panel investigation-details">
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 className="panel-title">Investigation Details</h2>
        {onClear && (
          <button onClick={onClear} style={{ background: 'transparent', border: '1px solid var(--border-subtle)', color: 'var(--text-muted)', cursor: 'pointer', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem' }}>
            Clear
          </button>
        )}
      </div>

      <div className="inv-grid">
        <div className="inv-row">
          <span className="inv-label">Request ID:</span>
          <span className="inv-value" style={{ fontFamily: 'monospace' }}>
            req_{event.event_id ? event.event_id.split('-')[0] : Math.random().toString(36).substr(2, 8)}
          </span>
        </div>

        <div className="inv-row">
          <span className="inv-label">Source:</span>
          <span className="inv-value highlight">{event.caller}</span>
        </div>

        <div className="inv-row">
          <span className="inv-label">Target:</span>
          <span className="inv-value highlight">{event.target}</span>
        </div>

        <div className="inv-row">
          <span className="inv-label">Identity:</span>
          <span className={`inv-value ${identityVerified ? 'text-green' : 'text-red'}`}>
            {identityVerified ? 'Valid DPoP' : 'Invalid / Mismatch'}
          </span>
        </div>

        <div className="inv-row">
          <span className="inv-label">Policy:</span>
          <span className="inv-value" style={{ fontFamily: 'monospace', color: '#94a3b8' }}>
            {policyName}
          </span>
        </div>

        <div className="inv-row">
          <span className="inv-label">Reason:</span>
          <span className="inv-value text-muted">{primaryReason}</span>
        </div>

        <div className="inv-row action-row">
          <span className="inv-label">Action:</span>
          <span className="inv-value" style={{ color: actionColor, fontWeight: 'bold' }}>
            {isBlocked ? 'Blocked' : 'Allowed'}
          </span>
        </div>
      </div>
    </div>
  );
}
