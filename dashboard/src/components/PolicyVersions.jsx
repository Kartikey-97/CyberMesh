import React from 'react';

export default function PolicyVersions({ versions, onRollback, currentCount }) {
  if (!versions || versions.length === 0) {
    return (
      <div className="policy-versions panel glass">
        <h2>Policy Snapshots</h2>
        <div className="empty-state">No policy snapshots available. Switch from Learning to Enforce to generate one.</div>
      </div>
    );
  }

  return (
    <div className="policy-versions panel glass">
      <h2>Policy Snapshots</h2>
      <div className="versions-list">
        {versions.map((ver, idx) => (
          <div key={ver.version} className={`version-card ${idx === 0 ? 'latest' : ''}`}>
            <div className="version-header">
              <span className="version-id">v{ver.version}</span>
              {idx === 0 && <span className="badge badge-active">Latest Snapshot</span>}
            </div>
            
            <div className="version-details">
              <div className="detail-row">
                <span className="detail-label">Label:</span>
                <span className="detail-value">{ver.label}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Rules:</span>
                <span className="detail-value font-mono">{ver.rule_count}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Date:</span>
                <span className="detail-value text-muted">{new Date(ver.timestamp * 1000).toLocaleString()}</span>
              </div>
            </div>

            <div className="version-actions">
              <button 
                className="btn-rollback" 
                onClick={() => onRollback(ver.version)}
                title="Restore this policy snapshot"
              >
                ROLLBACK TO V{ver.version}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
