import React, { useRef, useEffect } from 'react';

export default function PolicyGraph({ policy, lastEvent, theme }) {
  const containerRef = useRef(null);
  const canvasRef = useRef(null);
  const startTimeRef = useRef(Date.now()); // Persist start time across re-renders!

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!canvas || !container) return;
    
    const ctx = canvas.getContext('2d');
    let animationFrameId;
    
    const dpr = window.devicePixelRatio || 1;
    
    const resizeCanvas = () => {
      const rect = container.getBoundingClientRect();
      const width = rect.width || 600;
      const height = rect.height > 100 ? rect.height - 40 : 400; 
      
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      
      ctx.scale(dpr, dpr);
      return { width, height };
    };

    let { width, height } = resizeCanvas();

    setTimeout(() => {
       const dims = resizeCanvas();
       width = dims.width;
       height = dims.height;
    }, 100);

    const draw = () => {
      // Use the persisted start time so animation doesn't stutter on new events
      const time = Date.now() - startTimeRef.current;
      ctx.clearRect(0, 0, width, height);
      
      const centerX = width / 2;
      const centerY = height / 2;
      const padding = 60; 
      const radiusX = Math.max(50, (width / 2) - padding);
      const radiusY = Math.max(50, (height / 2) - padding);
      const radius = Math.min(radiusX, radiusY);

      let serviceNames = new Set(['user-service', 'billing-service', 'admin-service']);
      if (policy && policy.active_learned) {
        Object.keys(policy.active_learned).forEach(k => {
          const [caller, target] = k.split(' → ');
          if (caller) serviceNames.add(caller);
          if (target) serviceNames.add(target);
        });
      }

      const services = Array.from(serviceNames);
      
      const nodes = services.map((id, index) => {
        const angle = (index / services.length) * 2 * Math.PI - Math.PI / 2;
        return {
          id,
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle)
        };
      });

      // 1. Draw static background connections (faint)
      const activePolicy = policy?.active_learned || policy?.hardcoded_policy || {};
      Object.keys(activePolicy).forEach(k => {
        const [callerId, targetId] = k.split(' → ');
        const caller = nodes.find(n => n.id === callerId);
        const target = nodes.find(n => n.id === targetId);
        
        if (caller && target) {
          ctx.beginPath();
          ctx.strokeStyle = theme === 'light' ? 'rgba(15, 23, 42, 0.1)' : 'rgba(255, 255, 255, 0.05)';
          ctx.lineWidth = 1.5;
          ctx.moveTo(caller.x, caller.y);
          ctx.lineTo(target.x, target.y);
          ctx.stroke();
        }
      });

      // 2. Draw live threat traffic
      if (lastEvent) {
        const caller = nodes.find(n => n.id === lastEvent.caller);
        const target = nodes.find(n => n.id === lastEvent.target);
        if (caller && target) {
           const isBlock = lastEvent.decision === 'BLOCK';
           const isRecon = lastEvent.data?.recon_alert;
           
           if (isBlock || isRecon) {
             ctx.beginPath();
             if (isRecon) {
               ctx.strokeStyle = '#a855f7'; 
             } else if (isBlock) {
               ctx.strokeStyle = '#ef4444'; 
             }
             
             ctx.lineWidth = 2.5;
             ctx.setLineDash([10, 10]);
             ctx.lineDashOffset = -time / 15; 
             ctx.moveTo(caller.x, caller.y);
             ctx.lineTo(target.x, target.y);
             ctx.stroke();
             ctx.setLineDash([]); 
           }
        }
      }

      // 3. Draw nodes
      nodes.forEach(node => {
        const isEventActive = lastEvent && (lastEvent.caller === node.id || lastEvent.target === node.id);
        
        // Subtle ambient pulse for all nodes based on time
        const pulse = (Math.sin(time / 500) + 1) / 2; // 0 to 1

        ctx.beginPath();
        ctx.arc(node.x, node.y, 24, 0, 2 * Math.PI);
        ctx.fillStyle = theme === 'light' ? '#FFFFFF' : '#0f172a'; 
        ctx.fill();
        
        ctx.lineWidth = 2;
        let defaultStroke = theme === 'light' ? '#CBD5E1' : (pulse > 0.8 ? '#334155' : '#1e293b');
        ctx.strokeStyle = isEventActive ? '#ef4444' : defaultStroke;
        ctx.stroke();
        
        // Inner Circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, 10, 0, 2 * Math.PI);
        let defaultInner = theme === 'light' ? 'rgba(15, 23, 42, 0.1)' : 'rgba(51, 65, 85, 0.5)';
        ctx.fillStyle = isEventActive ? 'rgba(239, 68, 68, 0.4)' : defaultInner;
        ctx.fill();
        
        // Node Label
        ctx.fillStyle = isEventActive ? (theme === 'light' ? '#ef4444' : '#ffffff') : (theme === 'light' ? '#64748b' : '#94a3b8'); 
        ctx.font = '500 12px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(node.id, node.x, node.y + 42);
      });

      animationFrameId = requestAnimationFrame(draw);
    };
    
    animationFrameId = requestAnimationFrame(draw);
    
    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [policy, lastEvent, theme]);

  return (
    <div className="policy-graph panel" ref={containerRef} style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
      <div className="panel-header" style={{ flexShrink: 0, marginBottom: '8px' }}>
        <h2 className="panel-title">Service Mesh Topology</h2>
      </div>
      <div style={{ flex: 1, position: 'relative' }}>
        <canvas ref={canvasRef} style={{ position: 'absolute', top: 0, left: 0 }} />
      </div>
    </div>
  );
}
