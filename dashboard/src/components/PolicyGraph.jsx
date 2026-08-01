import React, { useRef, useEffect } from 'react';

export default function PolicyGraph({ policy, lastEvent }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let animationFrameId;
    let particles = [];
    
    // Extract nodes from policy
    let serviceNames = new Set(['user-service', 'billing-service', 'admin-service']); // defaults
    if (policy && policy.active_learned) {
      Object.keys(policy.active_learned).forEach(k => {
        const [caller, target] = k.split(' → ');
        if (caller) serviceNames.add(caller);
        if (target) serviceNames.add(target);
      });
    }

    const services = Array.from(serviceNames);
    const radius = 100;
    const centerX = 200;
    const centerY = 150;
    
    const nodes = services.map((id, index) => {
      const angle = (index / services.length) * 2 * Math.PI - Math.PI / 2;
      return {
        id,
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle)
      };
    });

    const draw = (time) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Draw edges based on policy
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.lineWidth = 2;
      
      const activePolicy = policy?.active_learned || policy?.hardcoded_policy || {};
      
      Object.keys(activePolicy).forEach(k => {
        const [callerId, targetId] = k.split(' → ');
        const caller = nodes.find(n => n.id === callerId);
        const target = nodes.find(n => n.id === targetId);
        
        if (caller && target) {
          ctx.beginPath();
          // Draw slightly curved line to see bidirectional
          const midX = (caller.x + target.x) / 2;
          const midY = (caller.y + target.y) / 2;
          const cpX = midX + (target.y - caller.y) * 0.2;
          const cpY = midY - (target.x - caller.x) * 0.2;
          
          ctx.moveTo(caller.x, caller.y);
          ctx.quadraticCurveTo(cpX, cpY, target.x, target.y);
          ctx.stroke();
        }
      });

      // Highlight if active
      if (lastEvent) {
        const caller = nodes.find(n => n.id === lastEvent.caller);
        const target = nodes.find(n => n.id === lastEvent.target);
        if (caller && target) {
           ctx.beginPath();
           if (lastEvent.decision === 'BLOCK') {
             ctx.strokeStyle = '#ff3366';
             ctx.setLineDash([5, 5]);
           } else {
             ctx.strokeStyle = '#00ff88';
             ctx.setLineDash([]);
           }
           ctx.moveTo(caller.x, caller.y);
           ctx.lineTo(target.x, target.y);
           ctx.stroke();
           ctx.setLineDash([]); // reset
        }
      }

      // Draw nodes
      nodes.forEach(node => {
        let isGlow = false;
        if (lastEvent && (lastEvent.caller === node.id || lastEvent.target === node.id)) {
          isGlow = true;
        }

        ctx.beginPath();
        ctx.arc(node.x, node.y, 20, 0, 2 * Math.PI);
        if (isGlow) {
          ctx.shadowBlur = 15;
          ctx.shadowColor = '#00d4ff';
        } else {
          ctx.shadowBlur = 0;
        }
        ctx.fillStyle = '#111827';
        ctx.fill();
        ctx.strokeStyle = '#00d4ff';
        ctx.stroke();
        
        ctx.shadowBlur = 0;
        ctx.fillStyle = '#e2e8f0';
        ctx.font = '12px Inter';
        ctx.textAlign = 'center';
        ctx.fillText(node.id, node.x, node.y + 35);
      });

      animationFrameId = requestAnimationFrame(draw);
    };
    
    draw();
    
    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [policy, lastEvent]);

  return (
    <div className="policy-graph panel">
      <h2>Service Mesh Graph</h2>
      <canvas ref={canvasRef} width={400} height={300} style={{ width: '100%', height: 'auto' }} />
    </div>
  );
}
