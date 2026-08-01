import React from 'react';

export default function ServiceCards({ services = {}, onAction, onRevoke }) {
  const serviceEntries = Object.entries(services);
  
  if (serviceEntries.length === 0) {
    return (
      <div className="service-cards-container">
        <div className="empty-state">No services registered yet.</div>
      </div>
    );
  }

  return (
    <div className="service-cards-container">
      {serviceEntries.map(([srvName, srvData]) => {
        const isRevoked = srvData.revoked;
        const isShadow = srvData.mode === 'shadow';

        return (
          <div key={srvName} className={`service-card panel glass ${isRevoked ? 'revoked-card' : ''}`}>
            <div className="service-header">
              <h3>{srvName}</h3>
              <div className="status-indicators">
                {isShadow ? (
                  <span className="badge badge-shadow" title="Shadow Mode (No Enforcement)">👻 Shadow</span>
                ) : (
                  <span className="badge badge-enforce" title="Full Zero Trust Enforcement">🛡️ Enforced</span>
                )}
                <span className={`status-dot ${isRevoked ? 'revoked' : 'active'}`}></span>
              </div>
            </div>
            
            <div className="service-actions">
              {isShadow ? (
                <button className="btn-promote" onClick={() => onAction(srvName, 'promote')}>
                  PROMOTE
                </button>
              ) : (
                <button className="btn-demote" onClick={() => onAction(srvName, 'demote')}>
                  DEMOTE
                </button>
              )}
              
              <button className="btn-revoke" onClick={() => onRevoke(srvName)}>
                REVOKE
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

