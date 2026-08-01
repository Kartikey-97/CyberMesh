import React from 'react';

export default function RiskExplanation({ event }) {
  if (!event || !event.reasons) return null;

  return (
    <div className="risk-explanation panel">
      <h2>Evaluation Checklist</h2>
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
