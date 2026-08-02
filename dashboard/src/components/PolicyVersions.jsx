import React from 'react';

export default function PolicyVersions({ versions, onRollback, currentCount }) {
  
  const activeCapabilities = [
    "DPoP Proof of Possession Required",
    "Dynamic JWT Authentication",
    "Contextual Threat Validation",
    "Continuous Behavior Decay"
  ];

  return (
    <div className="policy-versions">
      <div className="event-list" style={{ marginBottom: '24px', overflowY: 'visible' }}>
        {activeCapabilities.map((cap, idx) => (
          <div key={idx} className="policy-row" style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 14px' }}>
            <span className="policy-icon text-green" style={{ display: 'flex' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            </span>
            <span className="policy-name" style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{cap}</span>
          </div>
        ))}
        {currentCount > 0 && (
          <div className="policy-row" style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '10px 14px' }}>
            <span className="policy-icon text-green" style={{ display: 'flex' }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            </span>
            <span className="policy-name" style={{ color: 'var(--text-primary)', fontWeight: '500' }}>{currentCount} Learned Mesh Routing Rules Active</span>
          </div>
        )}
      </div>

      {versions && versions.length > 0 && (
        <>
          <h3 className="panel-title" style={{ fontSize: '1.05rem', marginBottom: '12px', color: 'var(--text-secondary)' }}>Policy Snapshots</h3>
          <div className="versions-list" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {versions.map((ver, idx) => (
              <div key={ver.version} className="service-card" style={{ cursor: 'default' }}>
                <div>
                  <h4 style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    v{ver.version} 
                    {idx === 0 && <span className="bg-blue-soft" style={{ padding: '2px 8px', borderRadius: '100px', fontSize: '0.65rem' }}>LATEST</span>}
                  </h4>
                  <p>{ver.label} &bull; {ver.rule_count} Rules</p>
                </div>
                <button 
                  className="panel-action-btn"
                  onClick={() => onRollback(ver.version)}
                >
                  ROLLBACK
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
