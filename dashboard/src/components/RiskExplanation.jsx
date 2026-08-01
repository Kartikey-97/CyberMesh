import React from 'react';

export default function RiskExplanation({ event }) {
  if (!event || !event.reasons) return null;

  const isRecon = event.data && event.data.recon_alert;

  return (
    <div className="risk-explanation panel glass">
      <h2>Evaluation Checklist</h2>
      
      {isRecon && (
        <div className="recon-alert-banner">
          <span className="pulse-red">🎯 RECONNAISSANCE DETECTED</span>
          <p className="text-muted" style={{fontSize: '0.8rem', marginTop: '4px'}}>
            Rapid probing of multiple novel endpoints detected from this caller.
          </p>
        </div>
      )}

      <div className="reasons-list">
        {event.reasons.map((reason, idx) => (
          <div key={idx} className={`reason-item ${reason.result === 'PASS' ? 'pass' : 'fail'}`}>
            <div className="reason-icon">{reason.result === 'PASS' ? '✓' : '✗'}</div>
            <div className="reason-content">
              <div className="reason-header">
                <span className="reason-check">{reason.check}</span>
                <span className={`reason-impact font-mono ${reason.score_impact < 0 ? 'text-red' : 'text-green'}`}>
                  {reason.score_impact > 0 ? '+' : ''}{reason.score_impact} pts
                </span>
              </div>
              <div className="reason-detail text-muted">{reason.detail}</div>
            </div>
          </div>
        ))}
        {event.reasons.length === 0 && <div className="text-muted">No explicit reasons provided.</div>}
      </div>
    </div>
  );
}
