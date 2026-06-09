import React, { useEffect, useState } from "react";
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Users, 
  Database, 
  Settings, 
  Terminal, 
  Search, 
  User, 
  Network, 
  AlertTriangle, 
  Bot, 
  ListTodo,
  Check,
  X,
  RefreshCw,
  Clock,
  Activity,
  ChevronRight,
  ShieldCheck,
  Globe,
  BookOpen,
  FileCode,
  Maximize2,
  Minimize2,
  Anchor,
  Move
} from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8088";
const TOKEN = import.meta.env.VITE_OSOP_TOKEN || "dev-token";

function PhaseProgressBar({ engagement }) {
  if (!engagement) return null;
  const phases = ["initialized", "reconnaissance", "vulnerability_discovery", "exploitation", "post_exploitation", "reporting", "completed"];
  const currentIndex = phases.indexOf(engagement.phase);
  if (currentIndex === -1) return null;
  
  const percentage = Math.round((currentIndex / (phases.length - 1)) * 100);

  return (
    <div className="w-32 lg:w-48 space-y-1">
      <div className="flex justify-between text-[9px] font-mono text-on-surface-variant">
        <span>PROGRESS</span>
        <span>{percentage}%</span>
      </div>
      <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
        <div 
          className="bg-primary-fixed h-full transition-all duration-500 shadow-[0_0_8px_#00f5ff]" 
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
    </div>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState("TACTICAL_GRAPH");
  const [approvals, setApprovals] = useState([]);
  const [agents, setAgents] = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [engagement, setEngagement] = useState(null);
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [attackPaths, setAttackPaths] = useState([]);
  const [wafProfiles, setWafProfiles] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [sandboxStatus, setSandboxStatus] = useState(null);
  const [systemConfig, setSystemConfig] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [command, setCommand] = useState("");
  const [activeTerminalTab, setActiveTerminalTab] = useState("Events");
  const [launchDomain, setLaunchDomain] = useState("");
  const [eduContent, setEduContent] = useState(null);
  const [showEduModal, setShowEduModal] = useState(false);
  const [isBriefingMode, setIsBriefingMode] = useState(false);

  // Terminal Mobility State
  const [terminalState, setTerminalState] = useState({
    isFloating: false,
    isMaximized: false,
    position: { x: 50, y: 50 },
    height: 192
  });

  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  const startDrag = (e) => {
    if (!terminalState.isFloating) return;
    setIsDragging(true);
    setDragOffset({
      x: e.clientX - terminalState.position.x,
      y: e.clientY - terminalState.position.y
    });
  };

  const onDrag = (e) => {
    if (!isDragging) return;
    setTerminalState(prev => ({
      ...prev,
      position: {
        x: e.clientX - dragOffset.x,
        y: e.clientY - dragOffset.y
      }
    }));
  };

  const stopDrag = () => setIsDragging(false);

  async function handleCommand(e) {
    if (e.key === 'Enter') {
      const parts = command.trim().split(" ");
      const cmd = parts[0].toLowerCase();
      const arg = parts[1];

      if (cmd === "launch" && arg) {
        await launchMission(arg);
      } else if (cmd === "learn" && arg) {
        await fetchEducation(arg);
      }
      setCommand("");
    }
  }

  async function fetchEducation(vulnClass) {
    try {
      const res = await fetch(`${API_BASE}/intelligence/vulnerability-edu/${vulnClass}`, {
        headers: { Authorization: `Bearer ${TOKEN}` }
      });
      if (res.ok) {
        const data = await res.json();
        setEduContent(data);
        setShowEduModal(true);
      }
    } catch (err) { console.error("Edu Fetch Error:", err); }
  }

  async function launchMission(domainInput) {
    const domain = domainInput.replace('https://', '').replace('http://', '').split('/')[0];
    try {
      const res = await fetch(`${API_BASE}/engagements`, {
        method: "POST",
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          engagement_id: `eng-${domain}-${Date.now()}`,
          domains: [domain],
          approval_required_for: ["rce", "sqli"],
          roe: {}
        })
      });
      const newEng = await res.json();
      await fetch(`${API_BASE}/engagements/${newEng.session_id}/transition?new_phase=reconnaissance`, {
        method: "POST",
        headers: { Authorization: `Bearer ${TOKEN}` }
      });
      await fetch(`${API_BASE}/tasks`, {
        method: "POST",
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          task_type: "full_recon",
          priority: 10,
          agent_type: "recon",
          payload: { domain },
          engagement_id: newEng.session_id
        }),
      });
      setLaunchDomain("");
      setIsBriefingMode(false);
      fetchData();
    } catch (err) {
      setError("Mission Launch Failed: " + err.message);
    }
  }

  async function simulatePath(pathId) {
    if (!engagement) return;
    try {
      await fetch(`${API_BASE}/tasks`, {
        method: "POST",
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          task_type: "validate_chain",
          priority: 10,
          agent_type: "attack_chain",
          payload: { path_id: pathId },
          engagement_id: engagement.session_id
        }),
      });
      alert("ATTACK_SIMULATION_INITIALIZED: " + pathId);
    } catch (err) { setError("Simulation Failed: " + err.message); }
  }

  function startNewMission() {
    setIsBriefingMode(true);
    setEngagement(null);
    setGraphData({ nodes: [], edges: [] });
    setAttackPaths([]);
  }

  async function printReport() {
    if (!engagement) return;
    try {
      const res = await fetch(`${API_BASE}/engagements/${engagement.session_id}/report`, {
        headers: { Authorization: `Bearer ${TOKEN}` }
      });
      if (res.ok) {
        const data = await res.json();
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
          <html>
            <head>
              <title>AI-OSOP Security Report</title>
              <style>
                body { font-family: 'Courier New', monospace; padding: 40px; line-height: 1.6; color: #333; }
                h1, h2, h3 { color: #000; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
                pre { background: #f4f4f4; padding: 15px; border-left: 4px solid #d00; white-space: pre-wrap; word-wrap: break-word; }
                .confidential { color: #d00; font-weight: bold; text-align: center; border: 2px dashed #d00; padding: 10px; margin-bottom: 30px; }
              </style>
            </head>
            <body>
              <div class="confidential">CONFIDENTIAL & PROPRIETARY // AI-OSOP GENERATED</div>
              <pre>${data.markdown}</pre>
              <script>
                window.onload = () => { setTimeout(() => window.print(), 500); };
              </script>
            </body>
          </html>
        `);
        printWindow.document.close();
      } else {
        alert("Report not ready yet.");
      }
    } catch (err) {
      console.error(err);
      alert("Failed to fetch report.");
    }
  }

  async function fetchData() {
    try {
      const [configRes, sandboxRes, engListRes] = await Promise.all([
        fetch(`${API_BASE}/system/config`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : null),
        fetch(`${API_BASE}/system/sandbox/status`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : null),
        fetch(`${API_BASE}/engagements`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : [])
      ]);

      setSystemConfig(configRes);
      setSandboxStatus(sandboxRes);

      const activeEng = Array.isArray(engListRes) && engListRes.length > 0 ? engListRes[engListRes.length - 1] : null;

      if (!isBriefingMode) {
        setEngagement(activeEng);
      }

      if (activeEng && !isBriefingMode) {
        const [appData, agentData, auditData, graphRes, pathsRes, wafRes, credsRes] = await Promise.all([       
          fetch(`${API_BASE}/approvals/pending`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : []),
          fetch(`${API_BASE}/agents`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : []),
          fetch(`${API_BASE}/engagements/${activeEng.session_id}/audit-log?limit=50`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : []),
          fetch(`${API_BASE}/engagements/${activeEng.session_id}/graph`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : { nodes: [], edges: [] }),
          fetch(`${API_BASE}/engagements/${activeEng.session_id}/attack-paths`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : []),
          fetch(`${API_BASE}/engagements/${activeEng.session_id}/waf-profiles`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : []),
          fetch(`${API_BASE}/engagements/${activeEng.session_id}/credentials`, { headers: { Authorization: `Bearer ${TOKEN}` } }).then(r => r.ok ? r.json() : [])
        ]);

        setApprovals(appData);
        setAgents(agentData);
        setAuditLog(auditData);
        setGraphData(graphRes);
        setAttackPaths(pathsRes);
        setWafProfiles(wafRes);
        setCredentials(credsRes);
      }
      setError("");
    } catch (err) {
      console.error("Fetch Error:", err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  async function resolveApproval(request, decision) {
    try {
      await fetch(`${API_BASE}/approvals/${request.id}/resolve`, {
        method: "POST",
        headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: request.id, decision, operator_id: "operator-1", notes: "Resolved via Command Core" }),
      });
      fetchData();
    } catch (err) { setError(err.message); }
  }

  return (
    <div className="bg-[#000000] text-[#e5e2e3] h-screen flex flex-col overflow-hidden font-mono text-[11px]">  
      <div className="scanline"></div>

      {/* Education Modal */}
      {showEduModal && eduContent && (
        <div className="modal-overlay">
          <div className="briefing-room border-secondary glow-secondary max-w-2xl animate-in zoom-in duration-300">
            <div className="flex justify-between items-start mb-6">
               <div className="flex items-center gap-3">
                  <BookOpen className="text-secondary" />
                  <h2 className="text-xl font-bold text-secondary uppercase tracking-widest">{eduContent.title}</h2>
               </div>
               <button onClick={() => setShowEduModal(false)} className="text-secondary hover:text-white p-2 border border-secondary/20"><X size={16}/></button>
            </div>
            <div className="space-y-6 overflow-y-auto max-h-[70vh] pr-4 custom-scrollbar">
               <div className="space-y-2">
                  <span className="text-[10px] font-bold opacity-40 uppercase tracking-widest">Description</span>
                  <p className="text-sm leading-relaxed">{eduContent.description}</p>
               </div>
               <div className="space-y-2">
                  <span className="text-[10px] font-bold text-tertiary uppercase tracking-widest">Impact_Assessment</span>
                  <p className="text-sm border-l-2 border-tertiary pl-3 bg-tertiary/5 py-2">{eduContent.impact}</p>
               </div>
               <div className="space-y-3">
                  <span className="text-[10px] font-bold text-primary-fixed uppercase tracking-widest">Exploitation_Playbook (Agent Steps)</span>
                  <div className="bg-black/60 border border-outline-variant p-4 space-y-3">
                     {eduContent.how_to_exploit.map((step, i) => (
                        <div key={i} className="flex gap-3 text-xs">
                           <span className="text-primary-fixed font-bold">{i+1}.</span>
                           <span className="opacity-80 font-mono">{step}</span>
                        </div>
                     ))}
                  </div>
               </div>
               <div className="p-4 bg-primary-fixed/5 border-t border-primary-fixed/20 text-center">
                  <span className="text-[9px] font-bold text-primary-fixed uppercase tracking-widest">Mission_Directive: System will autonomously execute these steps in Exhaustive_Mode.</span>
               </div>
            </div>
          </div>
        </div>
      )}

      {/* Briefing Room Modal */}
      {(isBriefingMode || (!engagement && !isLoading)) && (
        <div className="modal-overlay">
          <div className="briefing-room animate-in zoom-in duration-300">
            <div className="flex flex-col items-center gap-6">
              <div className="p-4 bg-primary-fixed/10 border border-primary-fixed rounded-full animate-pulse-neon">
                 <Globe size={48} className="text-primary-fixed" />
              </div>
              <div className="text-center space-y-2">
                <h2 className="text-xl font-bold text-primary-fixed tracking-[0.3em] uppercase">Tactical_Briefing</h2>
                <p className="text-[9px] opacity-40 uppercase tracking-widest">Awaiting engagement parameters to deploy agents.</p>
              </div>

              <div className="w-full space-y-4 mt-4">
                 <div className="bg-black border border-outline-variant p-4 focus-within:border-primary-fixed transition-colors">
                    <div className="text-[8px] font-bold opacity-30 uppercase mb-2">Primary_Target_Domain</div> 
                    <div className="flex items-center gap-3">
                       <span className="text-primary-fixed font-bold text-lg">&gt;</span>
                       <input
                         type="text"
                         autoFocus
                         className="bg-transparent border-none text-on-surface font-mono text-lg w-full focus:outline-none"
                         placeholder="DOMAIN_OR_IP..."
                         value={launchDomain}
                         onChange={(e) => setLaunchDomain(e.target.value)}
                         onKeyDown={(e) => e.key === 'Enter' && launchMission(launchDomain)}
                       />
                    </div>
                 </div>
                 <div className="p-3 border border-outline-variant bg-white/5">
                    <div className="flex items-center justify-between mb-2">
                       <span className="text-[9px] font-bold opacity-40 uppercase">Mission_Configuration</span> 
                       <span className="text-[8px] bg-primary-fixed text-black px-1 font-bold">EXHAUSTIVE_MODE</span>
                    </div>
                    <p className="text-[9px] opacity-60 leading-relaxed">System will discover and attempt to exploit ALL valid vulnerability vectors. Reporting phase will only trigger after the entire attack surface is exhausted.</p>
                 </div>
                 <button
                   onClick={() => launchMission(launchDomain)}
                   className="w-full bg-primary-fixed text-black py-4 font-bold text-xs uppercase tracking-[0.5em] hover:brightness-110 transition-all glow-primary"
                 >
                   Deploy_Agents
                 </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="h-10 bg-surface-container border-b border-outline-variant z-30 flex items-center justify-between px-4">
        <div className="flex items-center gap-4">
          <h1 className="text-[10px] font-bold text-primary-fixed tracking-widest uppercase">AI-OSOP // COMMAND_CORE_V3.0</h1>
          <div className="h-4 w-[1px] bg-outline-variant"></div>
          {engagement ? (
            <div className="flex gap-4">
               <div className="flex items-center gap-2"><span className="opacity-40">TARGET:</span><span className="text-primary-fixed uppercase">{engagement.scope.domains[0]}</span></div>
               <div className="flex items-center gap-2"><span className="opacity-40">PHASE:</span><span className="text-secondary uppercase">{engagement.phase}</span></div>
            </div>
          ) : <span className="opacity-20 uppercase animate-pulse">#_AWAITING_DEPLOYMENT...</span>}
        </div>
        <div className="flex items-center gap-4">
           <button
             onClick={startNewMission}
             className="bg-primary-fixed/10 border border-primary-fixed text-primary-fixed px-3 py-1 text-[9px] font-bold uppercase tracking-widest hover:bg-primary-fixed hover:text-black transition-all"
           >
             New_Mission
           </button>
           <div className="flex items-center gap-2">
              <span className="text-[8px] opacity-40 uppercase">Report:</span>
              <div className="w-16 h-1 bg-surface-container-highest overflow-hidden"><div className="h-full bg-primary-fixed" style={{width: engagement?.phase === 'completed' ? '100%' : '65%'}}></div></div>
           </div>
           {engagement?.phase === 'completed' && (
             <button onClick={printReport} className="text-[9px] bg-primary-fixed text-black px-2 py-0.5 font-bold hover:brightness-110 uppercase tracking-widest glow-primary">Print_PDF</button>
           )}
           <button className="p-1 hover:text-primary-fixed"><Settings size={14}/></button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className="w-52 border-r border-outline-variant bg-surface-container-low flex flex-col">
           <div className="p-2 border-b border-outline-variant bg-surface-container text-[9px] font-bold uppercase tracking-widest text-on-surface-variant">Fleet_Inventory</div>
           <div className="flex-1 overflow-y-auto p-3 space-y-5 custom-scrollbar">
              {agents.map(a => <AgentItem key={a.agent_id} agent={a} />)}
           </div>
           <div className="p-3 bg-black/40 space-y-2">
              <HealthItem label="Kernel_Filter" status={sandboxStatus?.ebpf_filter_active ? "up" : "down"} />   
              <HealthItem label="Memory_Graph" status="up" />
           </div>
        </aside>

        <main className="flex-1 flex flex-col pane-container border-r border-outline-variant">
           <div className="tab-nav">
              <TabNavItem label="TACTICAL_GRAPH" active={activeTab === "TACTICAL_GRAPH"} onClick={() => setActiveTab("TACTICAL_GRAPH")} />
              <TabNavItem label="PATH_EXPLORER" active={activeTab === "PATH_EXPLORER"} onClick={() => setActiveTab("PATH_EXPLORER")} />
              <TabNavItem label="ENTITY_DB" active={activeTab === "ENTITY_DB"} onClick={() => setActiveTab("ENTITY_DB")} />
           </div>

           <div className="tab-content terminal-grid">
              {activeTab === "TACTICAL_GRAPH" && (
                <div className="graph-canvas">
                   {/* 1. Statistics Overlay */}
                   <div className="absolute top-4 right-4 text-right border-r-2 border-primary-fixed/20 pr-3 z-30">
                      <div className="text-xl font-bold text-primary-fixed">{graphData.nodes.length}</div>      
                      <div className="text-[8px] opacity-40 uppercase">DATA_NODES_INDEXED</div>
                   </div>

                   {/* 2. Visual Orbits */}
                   <div className="graph-orbit w-[300px] h-[300px]"></div>
                   <div className="graph-orbit w-[600px] h-[600px]"></div>

                   {/* 3. Graph Logic */}
                   <div className="absolute inset-0 flex items-center justify-center">
                      <div className="relative">
                         {/* Target (Center) */}
                         <div className="node-container" style={{ transform: 'translate(-50%, -50%)' }}>        
                            <div className="node-icon text-primary-fixed border-2 glow-primary animate-pulse">  
                               <Globe size={24} />
                            </div>
                            <div className="mt-4 bg-black/80 border border-primary-fixed/40 px-3 py-1 text-[10px] font-bold text-primary-fixed uppercase tracking-widest whitespace-nowrap">
                               {engagement?.scope?.domains[0] || "OFFLINE"}
                            </div>
                         </div>

                         {/* Endpoints & Vulnerabilities (Orbits) */}
                         {graphData.nodes
                            .filter(n => !n.labels.includes('Asset'))
                            .slice(0, 40) // Limit to 40 nodes for readability
                            .map((node, index, filteredArray) => {

                            const isVuln = node.labels.includes('Vulnerability');
                            const orbitRadius = isVuln ? 280 : 160;

                            const sameTypeNodes = filteredArray.filter(n => (isVuln ? n.labels.includes('Vulnerability') : n.labels.includes('Endpoint')));
                            const typeIndex = sameTypeNodes.findIndex(n => n.id === node.id);
                            const angle = (typeIndex / Math.max(sameTypeNodes.length, 1)) * 2 * Math.PI;

                            const x = Math.cos(angle) * orbitRadius;
                            const y = Math.sin(angle) * orbitRadius;

                            return (
                               <div
                                 key={node.id}
                                 className="node-container"
                                 style={{
                                    transform: `translate(${x}px, ${y}px)`,
                                    marginLeft: '-12px',
                                    marginTop: '-12px'
                                 }}
                               >
                                  <div
                                    className={`node-icon ${isVuln ? 'text-tertiary border-tertiary glow-danger animate-pulse' : 'text-primary-fixed/60 border-primary-fixed/20'} bg-black p-1.5`}
                                    onClick={() => isVuln && fetchEducation(node.properties.vuln_type)}
                                  >
                                     {isVuln ? <ShieldAlert size={16} /> : <FileCode size={12} />}
                                  </div>
                                  <div className="node-label">
                                     <div className="flex items-center gap-2 bg-black border border-outline-variant p-1">
                                        <span className={`text-[7px] px-1 font-bold ${isVuln ? 'bg-tertiary text-white' : 'bg-primary-fixed text-black'}`}>{node.labels[0]}</span>
                                        <span className="text-[9px]">{node.properties.value || node.properties.url}</span>
                                     </div>
                                  </div>
                                  {/* Faint link to center */}
                                  <div
                                    className={`link-line ${isVuln ? 'opacity-20' : 'opacity-5'}`}
                                    style={{
                                      width: `${orbitRadius}px`,
                                      transform: `rotate(${angle + Math.PI}rad)`,
                                      left: 12,
                                      top: 12
                                    }}
                                  ></div>
                               </div>
                            );
                         })}
                      </div>
                   </div>

                   {/* 4. Legend */}
                   <div className="legend-box">
                      <div className="flex items-center gap-3 text-[8px] font-bold">
                         <div className="w-2 h-2 bg-primary-fixed border border-primary-fixed glow-primary"></div>
                         <span className="opacity-60 uppercase">Target_Asset</span>
                      </div>
                      <div className="flex items-center gap-3 text-[8px] font-bold">
                         <div className="w-2 h-2 border border-primary-fixed opacity-60"></div>
                         <span className="opacity-60 uppercase">Discovered_Endpoint</span>
                      </div>
                      <div className="flex items-center gap-3 text-[8px] font-bold">
                         <div className="w-2 h-2 bg-tertiary border border-tertiary glow-danger"></div>
                         <span className="text-tertiary uppercase">Active_Vulnerability</span>
                      </div>
                   </div>
                </div>
              )}

              {activeTab === "PATH_EXPLORER" && (
                <div className="h-full p-4 overflow-y-auto custom-scrollbar space-y-3">
                   {attackPaths.map((p, i) => (
                      <div key={p.id} className="bg-white/5 border border-outline-variant p-4 border-l-4 border-l-secondary flex justify-between items-center group hover:bg-secondary/5 transition-all">
                         <div className="space-y-1">
                            <div className="text-[10px] font-bold text-secondary">CHAIN_VECT_0{i+1}</div>       
                            <div className="text-[9px] opacity-40">{p.node_ids.length} Nodes in Path // {Math.round(p.total_time_estimate/60)}m Execution Est.</div>
                         </div>
                         <div className="text-right space-y-2">
                            <div className="text-lg font-bold text-tertiary">RISK: {p.risk_score.toFixed(1)}</div>
                            <button
                              onClick={() => simulatePath(p.id)}
                              className="bg-primary-fixed text-black px-3 py-1 text-[9px] font-bold uppercase tracking-widest hover:brightness-110"
                            >
                              Simulate
                            </button>
                         </div>
                      </div>
                   ))}
                   {attackPaths.length === 0 && <EmptyState icon={<Activity size={32}/>} label="Searching for critical attack paths..." />}
                </div>
              )}

              {activeTab === "ENTITY_DB" && (
                <div className="h-full p-2 overflow-y-auto custom-scrollbar grid grid-cols-3 gap-1">
                   {graphData.nodes.map(n => (
                      <div key={n.id} className="bg-surface-container/50 border border-outline-variant p-2 flex justify-between items-center text-[10px]">
                         <span className="truncate opacity-80">{n.properties.value || n.properties.url}</span>  
                         <span className="text-[8px] border border-outline-variant px-1 opacity-40 uppercase">{n.labels[0]}</span>
                      </div>
                   ))}
                </div>
              )}
           </div>
        </main>

        <aside className="w-80 flex flex-col bg-surface-container-low">
           <ModuleHeader label="WAF_INTELLIGENCE" icon={<Activity size={12}/>} />
           <div className="flex-1 overflow-y-auto p-4 space-y-6 custom-scrollbar">
              {wafProfiles.map(w => (
                 <div key={w.target} className="bg-black border border-outline-variant p-3 space-y-4">
                    <div className="flex justify-between items-center border-b border-outline-variant pb-2">    
                       <span className="text-[10px] font-bold text-primary-fixed">{w.waf_type}</span>
                       <span className="text-[8px] px-2 py-0.5 bg-secondary text-black font-bold animate-pulse">DETECTED</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                       <MiniStat label="BYPASS_RATE" value={`${Math.round(w.bypass_success_rate*100)}%`} />     
                       <MiniStat label="MUTATIONS" value={w.evolved_bypasses} />
                    </div>
                    <div className="space-y-2">
                       <span className="text-[8px] opacity-40 uppercase font-bold">Filter_Blocking_Patterns:</span>
                       <div className="flex flex-wrap gap-1.5">
                          {w.blocked_patterns.map(p => (
                             <span key={p} className="text-[8px] font-bold border border-tertiary/40 text-tertiary px-2 py-0.5 bg-tertiary/5">{p}</span>
                          ))}
                       </div>
                    </div>
                 </div>
              ))}
              {wafProfiles.length === 0 && <div className="text-center py-10 opacity-20 text-[9px] font-bold uppercase">Awaiting_WAF_Telemetry...</div>}
           </div>

           <ModuleHeader label="CREDENTIAL_VAULT" icon={<Database size={12}/>} borderTop />
           <div className="h-40 overflow-y-auto p-4 space-y-2 bg-[#050506] custom-scrollbar">
              {credentials.map(c => (
                 <div key={c.id} className="bg-white/5 border border-outline-variant p-2 flex flex-col gap-1 hover:border-secondary/60 hover:bg-secondary/5 transition-all group">
                    <div className="flex justify-between items-center">
                       <span className="text-[8px] font-bold uppercase text-secondary tracking-widest">{c.type}</span>
                       <span className="text-[7px] opacity-30 font-mono group-hover:opacity-100 uppercase">{c.found_on}</span>
                    </div>
                    <div className="text-[10px] font-mono break-all text-on-surface bg-black/40 p-1 border border-white/5">{c.value}</div>
                 </div>
              ))}
              {credentials.length === 0 && <div className="text-center py-10 opacity-10 uppercase text-[8px] font-bold tracking-[0.2em]">Zero_Secrets_Harvested</div>}
           </div>
           
           <div className="p-3 border-t border-outline-variant bg-black/60">
              <div className="flex justify-between items-center">
                 <span className="text-[9px] font-bold text-tertiary tracking-widest uppercase">Pending_Approvals</span>
                 <span className="bg-tertiary text-white px-3 py-1 font-bold text-xs glow-tertiary">{approvals.length}</span>
              </div>
           </div>
        </aside>
      </div>

      <footer 
        onMouseMove={onDrag}
        onMouseUp={stopDrag}
        onMouseLeave={stopDrag}
        style={{ 
          height: terminalState.isMaximized ? 'calc(100vh - 40px)' : `${terminalState.height}px`,
          position: terminalState.isFloating ? 'fixed' : 'relative',
          bottom: terminalState.isFloating ? 'auto' : 0,
          left: terminalState.isFloating ? `${terminalState.position.x}px` : 0,
          top: terminalState.isFloating ? `${terminalState.position.y}px` : 'auto',
          width: terminalState.isFloating ? '600px' : '100%',
          zIndex: 40,
          boxShadow: terminalState.isFloating ? '0 0 50px rgba(0,0,0,0.8), 0 0 20px rgba(57,255,20,0.2)' : 'none'
        }}
        className={`border-t border-outline-variant bg-[#000000] flex flex-col transition-[height] duration-300 ${terminalState.isFloating ? 'border border-primary-fixed/30 shadow-2xl' : ''}`}
      >
         <div 
           className={`h-7 bg-surface-container border-b border-outline-variant flex items-center px-4 gap-6 select-none ${terminalState.isFloating ? 'cursor-move' : ''}`}
           onMouseDown={startDrag}
         >
            <div className="flex gap-4 h-full">
              <button onClick={() => setActiveTerminalTab("Events")} className={`text-[9px] font-bold uppercase tracking-widest h-full px-2 transition-all ${activeTerminalTab === "Events" ? "text-primary-fixed border-t-2 border-t-primary" : "opacity-30"}`}>System_Audit</button>
              <button onClick={() => setActiveTerminalTab("Insight")} className={`text-[9px] font-bold uppercase tracking-widest h-full px-2 transition-all ${activeTerminalTab === "Insight" ? "text-primary-fixed border-t-2 border-t-primary" : "opacity-30"}`}>Agent_Reasoning</button>
            </div>
            
            <div className="flex-1 flex items-center justify-center pointer-events-none">
              {terminalState.isFloating && <Move size={10} className="text-primary-fixed opacity-30 animate-pulse" />}
            </div>

            <div className="flex items-center gap-3">
               <button 
                onClick={() => setTerminalState(p => ({...p, isMaximized: !p.isMaximized}))}
                className="p-1 hover:text-primary-fixed opacity-40 hover:opacity-100"
               >
                 {terminalState.isMaximized ? <Minimize2 size={12}/> : <Maximize2 size={12}/>}
               </button>
               <button 
                onClick={() => setTerminalState(p => ({...p, isFloating: !p.isFloating}))}
                className={`p-1 hover:text-primary-fixed transition-all ${terminalState.isFloating ? 'text-primary-fixed opacity-100' : 'opacity-40'}`}
               >
                 <Anchor size={12}/>
               </button>
               <div className="h-3 w-[1px] bg-outline-variant mx-1"></div>
               <div className="flex items-center gap-2"><span className="text-[8px] opacity-40 uppercase">Egress:</span><span className="text-tertiary font-bold">{sandboxStatus?.active_blocks || 0}</span></div>
            </div>
         </div>

         {!terminalState.isMaximized && !terminalState.isFloating && (
           <div 
             className="absolute top-0 left-0 right-0 h-1 cursor-ns-resize hover:bg-primary-fixed/30 transition-colors z-50"
             onMouseDown={(e) => {
               const startY = e.clientY;
               const startH = terminalState.height;
               const onMove = (moveEvent) => {
                 setTerminalState(p => ({...p, height: Math.max(100, startH - (moveEvent.clientY - startY))}));
               };
               const onUp = () => {
                 window.removeEventListener('mousemove', onMove);
                 window.removeEventListener('mouseup', onUp);
               };
               window.addEventListener('mousemove', onMove);
               window.addEventListener('mouseup', onUp);
             }}
           ></div>
         )}

         <div className="flex-1 p-3 font-mono text-[10px] overflow-y-auto custom-scrollbar">
            {activeTerminalTab === "Events" ? (
               <div className="space-y-0.5">
                  {auditLog.map(e => (
                     <div key={e.event_id || Math.random()} className="flex gap-2 group border-b border-white/5 pb-0.5">
                        <span className="text-primary-fixed opacity-30 min-w-[70px]">[{new Date(e.timestamp).toLocaleTimeString()}]</span>
                        <span className="text-secondary font-bold group-hover:text-secondary-fixed transition-colors min-w-[100px]">[{e.actor_id?.toUpperCase().slice(0, 15) || 'SYSTEM'}]</span>
                        <span className={`px-1 border border-white/5 uppercase text-[8px] min-w-[80px] text-center ${e.event_type.includes('fail') ? 'text-tertiary' : 'text-on-surface/40'}`}>{e.event_type}</span>
                        <span className="truncate flex-1 opacity-80 group-hover:opacity-100">{JSON.stringify(e.action || {})}</span>
                     </div>
                  ))}
                  <div className="flex items-center gap-2 mt-2">
                     <span className="text-primary-fixed font-bold animate-pulse">&gt;</span>
                     <input 
                       type="text" 
                       className="bg-transparent border-none text-primary-fixed focus:outline-none w-full"
                       placeholder="OPERATOR_INPUT_ACTIVE..."
                       value={command}
                       onChange={(e) => setCommand(e.target.value)}
                       onKeyDown={handleCommand}
                     />
                  </div>
               </div>
            ) : (
               <div className="text-primary-fixed/80 whitespace-pre-wrap leading-relaxed animate-in fade-in duration-500 bg-primary-fixed/5 p-4 border border-primary-fixed/10">
                  {auditLog.find(e => e.event_type === "task_completed" && e.result?.reasoning)?.result.reasoning || "# SYSTEM_STATE: Awaiting specialized agent analysis for strategic pivot mapping..."}
               </div>
            )}
         </div>
      </footer>
    </div>
  );
}

function TabNavItem({ label, active, onClick }) {
  return (
    <button onClick={onClick} className={`tab-nav-item ${active ? 'active' : ''}`}>{label}</button>
  )
}

function ModuleHeader({ label, icon, borderTop }) {
  return (
    <div className={`p-2.5 bg-surface-container flex items-center justify-between border-b border-outline-variant ${borderTop ? 'border-t' : ''}`}>
       <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-[0.2em]">{label}</span>
       <div className="text-primary-fixed opacity-40">{icon}</div>
    </div>
  )
}

function MiniStat({ label, value }) {
  return (
     <div className="bg-black/60 border border-outline-variant p-2 flex flex-col items-center group hover:border-primary-fixed/30 transition-colors">
        <span className="text-[7px] opacity-40 font-bold uppercase tracking-widest group-hover:text-primary-fixed/50">{label}</span>
        <span className="text-[14px] font-bold text-on-surface mt-1 group-hover:text-primary-fixed transition-all uppercase">{value}</span>
     </div>
  )
}

function HealthItem({ label, status }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[9px] font-bold text-on-surface-variant uppercase font-mono">{label}</span>
      <span className={`h-1.5 w-1.5 rounded-full ${status === 'up' ? 'bg-primary-fixed shadow-[0_0_8px_#39ff14]' : 'bg-tertiary shadow-[0_0_8px_#ff3131]'}`}></span>
    </div>
  );
}

function AgentItem({ agent }) {
  const progress = agent.status === "running" ? 65 : 0;
  const shortId = agent.agent_id.split('-').slice(0, 2).join('_');
  return (
    <div className="space-y-2 group">
      <div className="flex justify-between items-center">
        <span className="text-[10px] font-bold uppercase opacity-80 text-primary-fixed truncate max-w-[100px]">{shortId}</span>
        <span className={`text-[8px] font-bold ${agent.status === 'idle' ? 'text-on-surface-variant' : 'text-primary-fixed animate-pulse'}`}>{agent.status.toUpperCase()}</span>
      </div>
      <div className="w-full h-[1px] bg-surface-container-highest overflow-hidden">
        <div className="bg-primary-fixed h-full transition-all duration-1000 shadow-[0_0_5px_#39ff14]" style={{ width: `${progress}%` }}></div>
      </div>
    </div>
  );
}

function EmptyState({ icon, label }) {
  return (
    <div className="h-full flex flex-col items-center justify-center opacity-10 gap-3">
       {icon}
       <span className="text-[10px] font-bold uppercase tracking-widest">{label}</span>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
