import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import LiveFeed from './components/LiveFeed';
import PolicyGraph from './components/PolicyGraph';
import ThreatTimeline from './components/ThreatTimeline';
import TrustScorePanel from './components/TrustScorePanel';
import RiskExplanation from './components/RiskExplanation';
import ServiceCards from './components/ServiceCards';
import PolicyVersions from './components/PolicyVersions';
import { useEventStream } from './hooks/useEventStream';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || '';

function App() {
  const { events, lastEvent } = useEventStream(`${API_URL}/events`);
  const [metrics, setMetrics] = useState({});
  const [policy, setPolicy] = useState({});
  const [services, setServices] = useState({});
  const [policyVersions, setPolicyVersions] = useState([]);
  const [mode, setMode] = useState('enforce');
  const [selectedEvent, setSelectedEvent] = useState(null);

  const fetchData = async () => {
    try {
      const [metRes, polRes, srvRes, verRes] = await Promise.all([
        fetch(`${API_URL}/metrics`),
        fetch(`${API_URL}/policy`),
        fetch(`${API_URL}/services`),
        fetch(`${API_URL}/policy/versions`)
      ]);
      
      const [met, pol, srv, ver] = await Promise.all([
        metRes.json(), polRes.json(), srvRes.json(), verRes.json()
      ]);

      setMetrics(met);
      setPolicy(pol);
      setServices(srv);
      setPolicyVersions(ver.versions || []);
      if (met.mode) setMode(met.mode);
    } catch (e) {
      console.error('Failed to fetch data', e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
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
      fetchData(); // Immediately refresh to grab auto-snapshot if applicable
    } catch (e) {
      console.error('Failed to set mode', e);
    }
  };

  const handleServiceAction = async (serviceName, action) => {
    try {
      await fetch(`${API_URL}/services/${serviceName}/${action}`, { method: 'POST' });
      fetchData();
    } catch (e) {
      console.error(`Failed to ${action} ${serviceName}`, e);
    }
  };
  
  const handleRevoke = async (serviceName) => {
    try {
      await fetch(`${API_URL}/revoke/${serviceName}`, { method: 'POST' });
      fetchData();
    } catch (e) {
      console.error('Failed to revoke', e);
    }
  };

  const handleRollback = async (version) => {
    try {
      await fetch(`${API_URL}/policy/rollback/${version}`, { method: 'POST' });
      fetchData();
    } catch (e) {
      console.error(`Failed to rollback to ${version}`, e);
    }
  };

  const handleSelectEvent = (event) => {
    setSelectedEvent(event);
  };

  return (
    <div className="dashboard-layout">
      <Header mode={mode} metrics={metrics} />
      
      <div className="controls panel glass">
        <button className={`btn-mode ${mode === 'learning' ? 'active' : ''}`} onClick={() => handleModeChange('learning')}>Learning Mode</button>
        <button className={`btn-mode ${mode === 'enforce' ? 'active' : ''}`} onClick={() => handleModeChange('enforce')}>Enforce Mode</button>
        <button className={`btn-mode ${mode === 'demo-replay' ? 'active' : ''}`} onClick={() => handleModeChange('demo-replay')}>Demo Replay</button>
      </div>

      <div className="dashboard-content">
        <div className="left-column">
          <LiveFeed events={events} onSelectEvent={handleSelectEvent} selectedEventId={selectedEvent?.event_id} />
          <ServiceCards services={services} onAction={handleServiceAction} onRevoke={handleRevoke} />
        </div>

        <div className="right-column">
          <PolicyGraph policy={policy} lastEvent={lastEvent} />
          <PolicyVersions versions={policyVersions} onRollback={handleRollback} currentCount={policy.active_learned_count || 0} />
          
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

