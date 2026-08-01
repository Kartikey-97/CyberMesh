import React from 'react';

export default function TrustScorePanel({ event }) {
  if (!event) return null;

  const score = event.trust_score || 0;
  let color = '#00ff88'; // green
  if (score < 40) color = '#ff3366'; // red
  else if (score < 70) color = '#ffaa00'; // amber

  const hasDecay = event.data && event.data.decay_applied > 0;
  const rawBehavior = hasDecay ? event.data.behavior_score_raw : event.behavior_score;

  return (
    <div className="trust-score-panel panel glass">
      <h2>Trust Score Analysis</h2>
      
      <div className="gauge-container">
        <div className="circular-gauge" style={{ '--score': `${score}%`, '--gauge-color': color }}>
          <div className="inner-circle">
            <span className="score-value font-mono" style={{ color }}>{score.toFixed(1)}</span>
            <span className="score-label">TRUST</span>
          </div>
        </div>
      </div>

      <div className="band-label">
        Band: <span className={`badge badge-${event.band}`}>{event.band?.toUpperCase() || 'UNKNOWN'}</span>
      </div>

      <div className="sub-scores">
        <div className="sub-score">
          <span>Identity</span>
          <div className="bar-bg"><div className="bar-fill" style={{width: `${event.identity_score}%`}}></div></div>
          <span className="font-mono">{event.identity_score?.toFixed(1)}</span>
        </div>
        
        <div className="sub-score behavior-score-container">
          <span>Behavior</span>
          <div className="bar-bg">
            <div className="bar-fill" style={{width: `${event.behavior_score}%`}}></div>
          </div>
          <span className="font-mono">{event.behavior_score?.toFixed(1)}</span>
        </div>
        
        {hasDecay && (
          <div className="decay-indicator">
            <span className="decay-text pulse-amber" title="Trust decay applied due to inactivity">
              Drift: <s>{rawBehavior?.toFixed(1)}</s> → <strong>{event.behavior_score?.toFixed(1)}</strong>
            </span>
          </div>
        )}

        <div className="sub-score">
          <span>Context</span>
          <div className="bar-bg"><div className="bar-fill" style={{width: `${event.context_score}%`}}></div></div>
          <span className="font-mono">{event.context_score?.toFixed(1)}</span>
        </div>
      </div>
    </div>
  );
}

