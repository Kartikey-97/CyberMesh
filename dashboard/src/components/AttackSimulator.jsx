import React, { useState } from 'react';
import './AttackSimulator.css';

const API_URL = import.meta.env.VITE_API_URL || '';

export default function AttackSimulator() {
  const [trafficEnabled, setTrafficEnabled] = useState(false);

  const toggleTraffic = async () => {
    const newState = !trafficEnabled;
    setTrafficEnabled(newState);
    try {
      await fetch(`${API_URL}/simulate-traffic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState })
      });
    } catch (e) {
      console.error('Failed to toggle traffic', e);
    }
  };

  const simulateAttack = async (type) => {
    try {
      await fetch(`${API_URL}/simulate-attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: type })
      });
    } catch (e) {
      console.error('Failed to simulate attack', e);
    }
  };

  return (
    <div className="panel attack-simulator">
      <div className="panel-header">
        <h2 className="panel-title">Demo Controls</h2>
      </div>
      
      <div className="control-section">
        <div className="toggle-row">
          <div>
            <div className="toggle-label">Demo Mode</div>
            <div className="toggle-sub">Background traffic flow</div>
          </div>
          <button 
            className={`btn-toggle ${trafficEnabled ? 'active' : ''}`}
            onClick={toggleTraffic}
          >
            {trafficEnabled ? 'ON' : 'OFF'}
          </button>
        </div>
      </div>

      <div className="control-section">
        <div className="section-title">Attack Simulator</div>
        
        <button className="btn-attack" onClick={() => simulateAttack('dpop_replay')}>
          <div className="btn-attack-text">
            <strong>Steal & Replay Token</strong>
            <span>Test DPoP Replay Protection</span>
          </div>
        </button>

        <button className="btn-attack" onClick={() => simulateAttack('signature_mismatch')}>
          <div className="btn-attack-text">
            <strong>Forge Request Signature</strong>
            <span>Test PoP Verification</span>
          </div>
        </button>

        <button className="btn-attack" onClick={() => simulateAttack('lateral_movement')}>
          <div className="btn-attack-text">
            <strong>Lateral Movement Attempt</strong>
            <span>Test Zero-Trust Policy Engine</span>
          </div>
        </button>
      </div>
    </div>
  );
}
