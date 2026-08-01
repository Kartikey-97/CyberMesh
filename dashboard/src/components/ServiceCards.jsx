import React from 'react';

export default function ServiceCards({ services, revoked = [], onRevoke }) {
  // services is an array of service names
  return (
    <div className="service-cards-container">
      {services.map(srv => {
        const isRevoked = revoked.includes(srv);
        return (
        <div key={srv} className={`service-card panel ${isRevoked ? 'revoked-card' : ''}`}>
          <div className="service-header">
            <h3>{srv}</h3>
            <span className={`status-dot ${isRevoked ? 'revoked' : 'active'}`}></span>
          </div>
          <div className="service-actions">
            <button className="btn-revoke" onClick={() => onRevoke(srv)}>
              REVOKE ACCESS
            </button>
          </div>
        </div>
      )})}
    </div>
  );
}
