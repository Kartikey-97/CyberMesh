import React, { useState, useEffect } from 'react';
import HeaderMetrics from './components/HeaderMetrics';
import AttackSimulator from './components/AttackSimulator';
import IdentityStatus from './components/IdentityStatus';
import PolicyGraph from './components/PolicyGraph';
import LiveFeed from './components/LiveFeed';
import InvestigationDetails from './components/InvestigationDetails';
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
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [theme, setTheme] = useState('dark');

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
    } catch (e) {
      console.error('Failed to fetch data', e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  // Use the most recent event if none is selected for the investigation panel
  const displayEvent = selectedEvent || (events.length > 0 ? events[0] : null);

  return (
    <div className={`dashboard-layout-spog relative ${theme}-theme`}>
      
      {/* Top Header Ribbon */}
      <HeaderMetrics metrics={metrics} policyCount={policy.active_learned_count || 0} theme={theme} onThemeToggle={toggleTheme} />
      
      {/* 3-Column Storytelling Grid: Controls (20%) -> Protection (55%) -> Evidence (25%) */}
      <div className="story-grid">
        
        {/* Column 1: Controls & Status */}
        <div className="story-col col-controls">
          <AttackSimulator />
          <IdentityStatus services={services} />
          
          <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '220px', flexShrink: 0 }}>
            <div className="panel-header">
              <h2 className="panel-title">Active Policies</h2>
            </div>
            <div style={{ overflowY: 'auto', flex: 1, paddingRight: '8px' }}>
              {policy.active_learned && Object.keys(policy.active_learned).length > 0 ? (
                Object.keys(policy.active_learned).map(k => (
                  <div key={k} style={{ marginBottom: '8px', fontSize: '0.8rem', background: 'rgba(255,255,255,0.02)', padding: '6px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ color: '#10b981', fontWeight: 'bold' }}>ALLOW</span> {k}
                  </div>
                ))
              ) : (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Learning...</div>
              )}
              <div style={{ marginTop: '8px', fontSize: '0.8rem', background: 'rgba(239, 68, 68, 0.05)', padding: '6px', borderRadius: '4px', border: '1px solid rgba(239,68,68,0.2)' }}>
                <span style={{ color: '#ef4444', fontWeight: 'bold' }}>DENY</span> ALL OTHER TRAFFIC
              </div>
            </div>
          </div>
        </div>

        {/* Column 2: The Hero (Topology) */}
        <div className="story-col col-hero">
          <PolicyGraph policy={policy} lastEvent={lastEvent} theme={theme} />
        </div>

        {/* Column 3: Evidence (Alerts & Investigation) */}
        <div className="story-col col-evidence">
          <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: '350px' }}>
             <div className="panel-header">
               <h2 className="panel-title">Security Alerts</h2>
             </div>
             <LiveFeed 
               events={events} 
               onSelectEvent={(evt) => setSelectedEvent(selectedEvent?.event_id === evt.event_id ? null : evt)} 
               selectedEventId={selectedEvent?.event_id} 
             />
          </div>
          
          <div style={{ flex: 1 }}>
             <InvestigationDetails event={displayEvent} onClear={() => setSelectedEvent(null)} />
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
