import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import LiveFeed from './components/LiveFeed';
import PolicyGraph from './components/PolicyGraph';
import ThreatTimeline from './components/ThreatTimeline';
import TrustScorePanel from './components/TrustScorePanel';
import RiskExplanation from './components/RiskExplanation';
import ServiceCards from './components/ServiceCards';
import { useEventStream } from './hooks/useEventStream';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || '';

function App() {
  const { events, lastEvent } = useEventStream(`${API_URL}/events`);
  const [metrics, setMetrics] = useState({});
  const [policy, setPolicy] = useState({});
  const [revoked, setRevoked] = useState([]);
  const [mode, setMode] = useState('enforce');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchMetrics = async () => {
    try {
      const res = await fetch(`${API_URL}/metrics`);
      const data = await res.json();
      setMetrics(data);
      if (data.mode) setMode(data.mode);
    } catch (e) {
      console.error('Failed to fetch metrics', e);
    }
  };

  const fetchPolicy = async () => {
    try {
      const res = await fetch(`${API_URL}/policy`);
      const data = await res.json();
      setPolicy(data);
    } catch (e) {
      console.error('Failed to fetch policy', e);
    }
  };

  const fetchRevoked = async () => {
    try {
      const res = await fetch(`${API_URL}/revoked`);
      const data = await res.json();
      setRevoked(data.revoked_services || []);
    } catch (e) {
      console.error('Failed to fetch revoked', e);
    }
  };

  useEffect(() => {
    fetchMetrics();
    fetchPolicy();
    fetchRevoked();
    const interval = setInterval(() => {
      fetchMetrics();
      fetchPolicy();
      fetchRevoked();
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleModeChange = async (newMode) => {
    try {
      await fetch(`${API_URL}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: newMode })
      });
      setMode(newMode);
    } catch (e) {
      console.error('Failed to set mode', e);
    }
  };

  const handleRevoke = async (serviceName) => {
    try {
      await fetch(`${API_URL}/revoke/${serviceName}`, { method: 'POST' });
      fetchRevoked();
    } catch (e) {
      console.error('Failed to revoke', e);
    }
  };

  const handleSelectEvent = (event) => {
    setSelectedEvent(event);
  };

  const allServices = ['user-service', 'billing-service', 'admin-service'];

  return (
    <div className="dashboard-layout">
      <Header mode={mode} metrics={metrics} />
      
      <div className="controls panel">
        <button className={`btn-mode ${mode === 'learning' ? 'active' : ''}`} onClick={() => handleModeChange('learning')}>Learning Mode</button>
        <button className={`btn-mode ${mode === 'enforce' ? 'active' : ''}`} onClick={() => handleModeChange('enforce')}>Enforce Mode</button>
        <button className={`btn-mode ${mode === 'demo-replay' ? 'active' : ''}`} onClick={() => handleModeChange('demo-replay')}>Demo Replay</button>
      </div>

      <div className="dashboard-content">
        <div className="left-column">
          <LiveFeed events={events} onSelectEvent={handleSelectEvent} selectedEventId={selectedEvent?.event_id} />
          <ServiceCards services={allServices} revoked={revoked} onRevoke={handleRevoke} />
        </div>

        <div className="right-column">
          <PolicyGraph policy={policy} lastEvent={lastEvent} />
          
          {selectedEvent ? (
            <div className="analysis-panels">
              <TrustScorePanel event={selectedEvent} />
              <RiskExplanation event={selectedEvent} />
            </div>
          ) : (
            <ThreatTimeline events={events} />
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
