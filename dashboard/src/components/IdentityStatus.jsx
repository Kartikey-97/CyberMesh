import React from 'react';
import './IdentityStatus.css';

export default function IdentityStatus({ services }) {
  const serviceNames = Object.keys(services).length > 0 
    ? Object.keys(services) 
    : ['user-service', 'billing-service', 'admin-service', 'payment-gateway', 'database'];

  return (
    <div className="panel identity-status">
      <div className="panel-header">
        <h2 className="panel-title">Cryptographic Identities</h2>
      </div>
      <div className="identity-list">
        {serviceNames.map(svc => {
          const isDb = svc === 'database' || svc === 'payment-gateway';
          return (
            <div key={svc} className="identity-row">
              <div className="svc-info">
                <span className="svc-name">{svc}</span>
                <span className="svc-token">
                  {isDb ? 'External / Unmanaged' : 'DPoP RS256'}
                </span>
              </div>
              <div className="svc-status">
                {isDb ? (
                  <span className="status-badge gray">Unverified</span>
                ) : (
                  <span className="status-badge green">✓ Verified</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
