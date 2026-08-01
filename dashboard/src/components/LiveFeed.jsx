import React, { useRef, useEffect } from 'react';

export default function LiveFeed({ events, onSelectEvent, selectedEventId }) {
  const feedRef = useRef(null);

  useEffect(() => {
    // Optional auto-scroll behavior could be added here
  }, [events]);

  return (
    <div className="live-feed panel">
      <h2>Live Events</h2>
      <div className="table-container" ref={feedRef}>
        <table className="feed-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Flow</th>
              <th>Path</th>
              <th>Decision</th>
              <th>Trust</th>
              <th>Lat (ms)</th>
            </tr>
          </thead>
          <tbody>
            {events.map((evt, idx) => (
              <tr
                key={evt.event_id || idx}
                className={`row-${evt.decision?.toLowerCase()} animate-slide-down ${selectedEventId === evt.event_id ? 'selected' : ''}`}
                onClick={() => onSelectEvent(evt)}
              >
                <td className="font-mono text-muted">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                <td className="font-mono">{evt.caller} <span className="text-muted">→</span> {evt.target}</td>
                <td className="font-mono">{evt.method} {evt.path}</td>
                <td>
                  <span className={`badge badge-${evt.decision?.toLowerCase()}`}>{evt.decision}</span>
                </td>
                <td className="font-mono">{evt.trust_score?.toFixed(1)}</td>
                <td className="font-mono">{evt.latency_ms?.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && <div className="empty-state">Waiting for events...</div>}
      </div>
    </div>
  );
}
