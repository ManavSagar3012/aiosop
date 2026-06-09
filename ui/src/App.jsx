import React, { useState, useEffect, useRef } from "react";

export default function App() {
  const [activeTab, setActiveTab] = useState("tactical");
  const [terminalTab, setTerminalTab] = useState("audit");
  const [approvalState, setApprovalState] = useState("initial"); // initial, pending, success
  const [vulnMapActive, setVulnMapActive] = useState(false);
  const [flickerCard, setFlickerCard] = useState(false);

  const terminalRef = useRef(null);

  // Auto-scroll terminal
  useEffect(() => {
    const interval = setInterval(() => {
      if (terminalRef.current) {
        if (
          terminalRef.current.scrollTop + terminalRef.current.clientHeight >=
          terminalRef.current.scrollHeight - 20
        ) {
          terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
      }
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleAuthorize = () => {
    setApprovalState("pending");
    setTimeout(() => {
      setApprovalState("success");
    }, 1500);
  };

  const handleReject = () => {
    setFlickerCard(true);
    setTimeout(() => setFlickerCard(false), 500);
    alert("ACTION REJECTED BY OPERATOR");
  };

  return (
    <div className="flex flex-col h-screen w-full relative z-10 border border-outline-variant">
      <div className="scanline"></div>

      {/* TOP APP BAR */}
      <header className="flex justify-between items-center w-full px-margin h-16 bg-background border-b border-outline-variant shrink-0 relative z-20">
        <div className="flex items-center gap-8">
          <div className="font-display-lg text-display-lg text-primary-fixed tracking-tighter uppercase">
            AI-OSOP // COMMAND CORE
          </div>
          <div className="flex flex-col">
            <div className="flex justify-between items-end mb-1">
              <span className="font-label-caps text-label-caps text-on-surface-variant">
                TARGET: ALPHA-CORP.COM
              </span>
              <span className="font-label-caps text-label-caps text-primary-container">
                PHASE: EXPLOITATION
              </span>
            </div>
            <div className="w-64 h-1 bg-surface-variant relative overflow-hidden">
              <div
                className="absolute top-0 left-0 h-full bg-primary-container glow-cyan"
                style={{ width: "65%" }}
              ></div>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <button className="bg-primary-container text-on-primary-fixed px-4 py-2 font-label-caps text-label-caps hover:brightness-110 transition-all active:scale-95">
            NEW MISSION
          </button>
          <button className="border border-outline text-on-surface px-4 py-2 font-label-caps text-label-caps hover:bg-surface-container-high transition-all">
            PRINT REPORT
          </button>
          <button className="bg-error text-on-primary px-4 py-2 font-label-caps text-label-caps glow-red hover:brightness-125 transition-all">
            EMERGENCY HALT
          </button>
          <div className="flex gap-2 ml-4">
            <span
              className="material-symbols-outlined text-on-surface-variant cursor-pointer hover:text-primary transition-colors"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              settings
            </span>
            <span
              className="material-symbols-outlined text-on-surface-variant cursor-pointer hover:text-primary transition-colors"
              style={{ fontVariationSettings: "'FILL' 1" }}
            >
              notifications_active
            </span>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden relative z-20">
        {/* SIDEBAR NAV (LEFT) */}
        <aside className="flex flex-col h-full w-64 bg-surface-container-low border-r border-outline-variant py-gutter shrink-0 overflow-y-auto">
          <div className="px-gutter mb-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 bg-primary-fixed-dim flex items-center justify-center">
                <span className="material-symbols-outlined text-on-primary-fixed">
                  smart_toy
                </span>
              </div>
              <div>
                <div className="font-label-caps text-label-caps text-primary">
                  OPERATOR_01
                </div>
                <div className="font-code-sm text-code-sm text-on-surface-variant">
                  RANK: ELITE
                </div>
              </div>
            </div>
            <div className="mb-8">
              <div className="font-label-caps text-label-caps text-on-surface-variant mb-4 border-b border-outline-variant pb-1">
                FLEET INVENTORY
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between group cursor-pointer">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-primary-container animate-pulse"></div>
                    <span className="font-code-sm text-code-sm text-primary group-hover:underline">
                      Recon_Agent
                    </span>
                  </div>
                  <span className="font-code-sm text-[10px] text-on-surface-variant">
                    EXECUTING
                  </span>
                </div>
                <div className="flex items-center justify-between group cursor-pointer">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-on-surface-variant"></div>
                    <span className="font-code-sm text-code-sm text-on-surface-variant group-hover:text-primary">
                      Exploit_Agent
                    </span>
                  </div>
                  <span className="font-code-sm text-[10px] text-on-surface-variant">
                    STANDBY
                  </span>
                </div>
                <div className="flex items-center justify-between group cursor-pointer">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-error animate-pulse"></div>
                    <span className="font-code-sm text-code-sm text-on-surface-variant group-hover:text-error">
                      Payload_Agent
                    </span>
                  </div>
                  <span className="font-code-sm text-[10px] text-on-surface-variant">
                    AWAITING
                  </span>
                </div>
              </div>
            </div>

            {/* INTERACTIVE RCE APPROVAL FLOW */}
            <div
              className={`mb-8 border p-3 relative overflow-hidden transition-all duration-300 ${
                flickerCard ? "flicker" : ""
              } ${
                approvalState === "success"
                  ? "border-secondary-container bg-secondary-container/5"
                  : "border-error bg-error-container/10"
              }`}
            >
              <div
                className={`absolute top-0 left-0 w-full h-1 opacity-50 ${
                  approvalState === "success"
                    ? "bg-secondary-container/20"
                    : "caution-border"
                }`}
              ></div>

              {approvalState === "initial" && (
                <div>
                  <div className="font-label-caps text-label-caps text-error mb-2">
                    HUMAN APPROVALS
                  </div>
                  <div className="font-code-sm text-code-sm text-on-surface mb-3 uppercase font-bold leading-tight">
                    RCE EXECUTION APPROVAL REQUIRED
                  </div>
                  <div className="flex gap-2">
                    <button
                      className="flex-1 bg-secondary-container text-on-secondary py-1 font-label-caps text-[10px] hover:brightness-110 active:scale-95 transition-all glow-green"
                      onClick={handleAuthorize}
                    >
                      AUTHORIZE
                    </button>
                    <button
                      className="flex-1 border border-error text-error py-1 font-label-caps text-[10px] hover:bg-error/10 active:scale-95 transition-all"
                      onClick={handleReject}
                    >
                      REJECT
                    </button>
                  </div>
                </div>
              )}

              {approvalState === "pending" && (
                <div className="py-2 text-center">
                  <div className="flex justify-center mb-2">
                    <span className="material-symbols-outlined text-primary-container animate-spin">
                      sync
                    </span>
                  </div>
                  <div className="font-label-caps text-[10px] text-primary-container animate-pulse">
                    PENDING BIOMETRIC VERIFICATION...
                  </div>
                </div>
              )}

              {approvalState === "success" && (
                <div className="py-1">
                  <div className="flex items-center gap-2 text-secondary-container mb-1">
                    <span className="material-symbols-outlined text-[16px]">
                      check_circle
                    </span>
                    <span className="font-label-caps text-[10px]">
                      MISSION AUTHORIZED
                    </span>
                  </div>
                  <div className="font-code-sm text-[9px] text-on-surface-variant uppercase">
                    Key: OSOP-882-VERIFIED
                  </div>
                </div>
              )}
            </div>

            <div>
              <div className="font-label-caps text-label-caps text-on-surface-variant mb-4 border-b border-outline-variant pb-1">
                SYSTEM HEALTH
              </div>
              <div className="flex gap-4">
                <div className="flex flex-col items-center gap-1 group cursor-help">
                  <div className="w-3 h-3 bg-primary-container glow-cyan group-hover:scale-125 transition-transform"></div>
                  <span className="text-[9px] font-label-caps text-on-surface-variant">
                    SANDBOX
                  </span>
                </div>
                <div className="flex flex-col items-center gap-1 group cursor-help">
                  <div className="w-3 h-3 bg-primary-container glow-cyan group-hover:scale-125 transition-transform"></div>
                  <span className="text-[9px] font-label-caps text-on-surface-variant">
                    EBPF
                  </span>
                </div>
                <div className="flex flex-col items-center gap-1 group cursor-help">
                  <div className="w-3 h-3 bg-primary-container glow-cyan group-hover:scale-125 transition-transform"></div>
                  <span className="text-[9px] font-label-caps text-on-surface-variant">
                    DB
                  </span>
                </div>
              </div>
            </div>
          </div>
          <div className="mt-auto px-gutter">
            <button className="w-full py-3 border border-primary-fixed text-primary-fixed font-label-caps text-label-caps hover:bg-primary-fixed/10 transition-colors active:scale-95">
              NEW AGENT
            </button>
          </div>
        </aside>

        {/* MAIN CONTENT */}
        <main className="flex flex-col flex-1 overflow-hidden">
          {/* TABS */}
          <div className="flex bg-surface-container h-12 border-b border-outline-variant shrink-0">
            <button
              className={`px-8 flex items-center border-r border-outline-variant font-label-caps text-label-caps transition-all ${
                activeTab === "tactical"
                  ? "text-primary border-b-2 border-primary-container bg-surface-variant"
                  : "text-on-surface-variant hover:bg-surface-container-high"
              }`}
              onClick={() => setActiveTab("tactical")}
            >
              TACTICAL GRAPH
            </button>
            <button
              className={`px-8 flex items-center border-r border-outline-variant font-label-caps text-label-caps transition-all ${
                activeTab === "explorer"
                  ? "text-primary border-b-2 border-primary-container bg-surface-variant"
                  : "text-on-surface-variant hover:bg-surface-container-high"
              }`}
              onClick={() => setActiveTab("explorer")}
            >
              ATTACK PATH EXPLORER
            </button>
            <button
              className={`px-8 flex items-center border-r border-outline-variant font-label-caps text-label-caps transition-all ${
                activeTab === "entity"
                  ? "text-primary border-b-2 border-primary-container bg-surface-variant"
                  : "text-on-surface-variant hover:bg-surface-container-high"
              }`}
              onClick={() => setActiveTab("entity")}
            >
              ENTITY DB
            </button>
          </div>

          <div className="flex-1 overflow-hidden relative">
            {/* TAB 1: TACTICAL GRAPH */}
            {activeTab === "tactical" && (
              <div className="h-full w-full flex flex-col p-6">
                <div
                  className={`flex-1 relative border overflow-hidden rounded-lg transition-all duration-700 ${
                    vulnMapActive
                      ? "bg-error-container/10 border-error"
                      : "bg-black border-outline-variant"
                  }`}
                >
                  <div className="absolute inset-0 opacity-40 bg-[radial-gradient(#1a1a1a_1px,transparent_1px)] [background-size:40px_40px]"></div>

                  {/* Interactive Node Example 1 */}
                  <div className="absolute top-1/3 left-1/4">
                    <div className="node-trigger w-4 h-4 bg-primary-fixed glow-cyan cursor-pointer hover:scale-150 transition-transform"></div>
                    <div className="node-inspect absolute top-6 left-0 z-20 w-48 bg-surface-container border border-primary-container p-3 backdrop-blur-md">
                      <div className="font-label-caps text-[10px] text-primary-container mb-1">
                        NODE_ALPHA_05
                      </div>
                      <div className="font-code-sm text-[11px] space-y-1">
                        <div className="flex justify-between">
                          <span>IP:</span>{" "}
                          <span className="text-primary">10.0.42.101</span>
                        </div>
                        <div className="flex justify-between">
                          <span>SRV:</span>{" "}
                          <span className="text-primary">HTTP, SSH</span>
                        </div>
                        <div className="flex justify-between">
                          <span>RISK:</span>{" "}
                          <span className="text-error">CRITICAL</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Interactive Node Example 2 */}
                  <div className="absolute bottom-1/4 right-1/3">
                    <div className="node-trigger w-3 h-3 bg-secondary-fixed cursor-pointer hover:scale-150 transition-transform"></div>
                    <div className="node-inspect absolute bottom-6 right-0 z-20 w-48 bg-surface-container border border-secondary-fixed p-3 backdrop-blur-md">
                      <div className="font-label-caps text-[10px] text-secondary-fixed mb-1">
                        ENDPOINT_BETA_21
                      </div>
                      <div className="font-code-sm text-[11px] space-y-1">
                        <div className="flex justify-between">
                          <span>IP:</span>{" "}
                          <span className="text-primary">192.168.1.105</span>
                        </div>
                        <div className="flex justify-between">
                          <span>OS:</span>{" "}
                          <span className="text-primary">LINUX X64</span>
                        </div>
                        <div className="flex justify-between">
                          <span>AUTH:</span>{" "}
                          <span className="text-secondary-fixed">BYPASSED</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Legend & Controls */}
                  <div className="absolute top-4 right-4 bg-surface/80 backdrop-blur-md p-4 border border-outline-variant">
                    <div className="font-label-caps text-label-caps text-on-surface-variant mb-3">
                      GRAPH LEGEND
                    </div>
                    <div className="space-y-2 mb-6">
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 bg-primary-fixed glow-cyan"></div>
                        <span className="font-code-sm text-code-sm">
                          TARGET NODE
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 bg-secondary-fixed"></div>
                        <span className="font-code-sm text-code-sm">
                          ENDPOINT
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 bg-error glow-red"></div>
                        <span className="font-code-sm text-code-sm">
                          VULNERABILITY
                        </span>
                      </div>
                    </div>
                    <button
                      className={`w-full border py-2 font-label-caps text-[10px] transition-all active:scale-95 ${
                        vulnMapActive
                          ? "border-error text-error hover:bg-error/10"
                          : "border-primary-container text-primary-container hover:bg-primary-container/10"
                      }`}
                      onClick={() => setVulnMapActive(!vulnMapActive)}
                    >
                      {vulnMapActive
                        ? "EXIT VULNERABILITY MAP"
                        : "FULLSCREEN VULN MAP"}
                    </button>
                  </div>

                  {/* Overlay HUD stats */}
                  <div className="absolute bottom-4 left-4 font-code-sm text-code-sm text-primary flex gap-8">
                    <div>NODES: 1,204</div>
                    <div>EDGES: 4,921</div>
                    <div>LATENCY: 14MS</div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: EXPLORER (Detailed Vertical Kill Chain) */}
            {activeTab === "explorer" && (
              <div className="h-full w-full p-8 overflow-y-auto terminal-scroll">
                <div className="max-w-3xl mx-auto space-y-0">
                  {/* RECON */}
                  <div className="relative flex gap-8">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 border border-primary-container bg-primary-container/20 flex items-center justify-center text-primary-container glow-cyan">
                        <span className="material-symbols-outlined text-[20px]">
                          search
                        </span>
                      </div>
                      <div className="w-px h-24 bg-primary-container"></div>
                    </div>
                    <div className="pt-1 pb-12 flex-1">
                      <div className="flex justify-between items-start mb-1">
                        <div>
                          <div className="font-label-caps text-label-caps text-primary-container">
                            PHASE 01 // RECONNAISSANCE
                          </div>
                          <div className="font-headline-md text-headline-md text-primary">
                            SUBDOMAIN ENUMERATION
                          </div>
                        </div>
                        <span className="px-2 py-0.5 bg-primary-container/10 text-primary-container font-label-caps text-[9px] border border-primary-container/30">
                          COMPLETED
                        </span>
                      </div>
                      <div className="font-code-sm text-code-sm text-on-surface-variant grid grid-cols-2 gap-4 mt-2 bg-white/5 p-3">
                        <div>
                          Target:{" "}
                          <span className="text-primary">alpha-corp.com</span>
                        </div>
                        <div>
                          Found: <span className="text-primary">42 Assets</span>
                        </div>
                        <div className="col-span-2">
                          Tool:{" "}
                          <span className="text-primary">
                            Amass / Assetfinder / OSINT-ML
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* WEAPONIZATION */}
                  <div className="relative flex gap-8">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 border border-primary-container bg-primary-container/20 flex items-center justify-center text-primary-container glow-cyan">
                        <span className="material-symbols-outlined text-[20px]">
                          architecture
                        </span>
                      </div>
                      <div className="w-px h-24 bg-primary-container"></div>
                    </div>
                    <div className="pt-1 pb-12 flex-1">
                      <div className="flex justify-between items-start mb-1">
                        <div>
                          <div className="font-label-caps text-label-caps text-primary-container">
                            PHASE 02 // WEAPONIZATION
                          </div>
                          <div className="font-headline-md text-headline-md text-primary">
                            PAYLOAD CRAFTING
                          </div>
                        </div>
                        <span className="px-2 py-0.5 bg-primary-container/10 text-primary-container font-label-caps text-[9px] border border-primary-container/30">
                          COMPLETED
                        </span>
                      </div>
                      <div className="font-code-sm text-code-sm text-on-surface-variant grid grid-cols-2 gap-4 mt-2 bg-white/5 p-3">
                        <div>
                          Payload:{" "}
                          <span className="text-primary">
                            msf-venom-x64-custom
                          </span>
                        </div>
                        <div>
                          Encoder:{" "}
                          <span className="text-primary">
                            Shikata_ga_nai (3 iterations)
                          </span>
                        </div>
                        <div className="col-span-2">
                          Signature:{" "}
                          <span className="text-primary">
                            Polymorphic Bypass v2.1
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* DELIVERY */}
                  <div className="relative flex gap-8">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 border border-primary-container bg-primary-container/20 flex items-center justify-center text-primary-container glow-cyan">
                        <span className="material-symbols-outlined text-[20px]">
                          outgoing_mail
                        </span>
                      </div>
                      <div className="w-px h-24 bg-primary-container"></div>
                    </div>
                    <div className="pt-1 pb-12 flex-1">
                      <div className="flex justify-between items-start mb-1">
                        <div>
                          <div className="font-label-caps text-label-caps text-primary-container">
                            PHASE 03 // DELIVERY
                          </div>
                          <div className="font-headline-md text-headline-md text-primary">
                            SSRF CHAIN INJECTION
                          </div>
                        </div>
                        <span className="px-2 py-0.5 bg-primary-container/10 text-primary-container font-label-caps text-[9px] border border-primary-container/30 animate-pulse">
                          ACTIVE
                        </span>
                      </div>
                      <div className="font-code-sm text-code-sm text-on-surface-variant grid grid-cols-2 gap-4 mt-2 bg-white/5 p-3">
                        <div>
                          Vector:{" "}
                          <span className="text-primary">
                            /api/v1/fetch?url=
                          </span>
                        </div>
                        <div>
                          Target:{" "}
                          <span className="text-primary">
                            internal-proxy-01.local
                          </span>
                        </div>
                        <div className="col-span-2">
                          Status:{" "}
                          <span className="text-primary">
                            Exfiltrating Metadata...
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* PENDING STEPS */}
                  <div className="relative flex gap-8 opacity-40">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 border border-outline-variant bg-surface-variant flex items-center justify-center text-on-surface-variant">
                        <span className="material-symbols-outlined text-[20px]">
                          lock
                        </span>
                      </div>
                      <div className="w-px h-24 bg-outline-variant"></div>
                    </div>
                    <div className="pt-1 pb-12 flex-1">
                      <div className="font-label-caps text-label-caps text-on-surface-variant">
                        PHASE 04 // EXPLOITATION
                      </div>
                      <div className="font-headline-md text-headline-md text-on-surface-variant">
                        RCE EXECUTION
                      </div>
                    </div>
                  </div>

                  <div className="relative flex gap-8 opacity-40">
                    <div className="flex flex-col items-center">
                      <div className="w-10 h-10 border border-outline-variant bg-surface-variant flex items-center justify-center text-on-surface-variant">
                        <span className="material-symbols-outlined text-[20px]">
                          settings_input_component
                        </span>
                      </div>
                    </div>
                    <div className="pt-1 flex-1">
                      <div className="font-label-caps text-label-caps text-on-surface-variant">
                        PHASE 05 // INSTALLATION
                      </div>
                      <div className="font-headline-md text-headline-md text-on-surface-variant">
                        PERSISTENCE ESTABLISHMENT
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 3: ENTITY DB */}
            {activeTab === "entity" && (
              <div className="h-full w-full p-6 overflow-hidden flex flex-col">
                <div className="border border-outline-variant overflow-hidden flex-1 flex flex-col">
                  <table className="w-full text-left font-code-sm text-code-sm">
                    <thead className="bg-surface-container-high border-b border-outline-variant">
                      <tr>
                        <th className="p-3 font-label-caps text-label-caps text-on-surface-variant">
                          IP_ADDRESS
                        </th>
                        <th className="p-3 font-label-caps text-label-caps text-on-surface-variant">
                          HOSTNAME
                        </th>
                        <th className="p-3 font-label-caps text-label-caps text-on-surface-variant">
                          STATUS
                        </th>
                        <th className="p-3 font-label-caps text-label-caps text-on-surface-variant">
                          RISK
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-black/40 overflow-y-auto">
                      <tr className="border-b border-outline-variant/30 hover:bg-surface-variant transition-colors cursor-pointer group">
                        <td className="p-3 text-primary group-hover:glow-cyan">
                          10.0.42.101
                        </td>
                        <td className="p-3">api.alpha-corp.com</td>
                        <td className="p-3">
                          <span className="text-primary-container">PROBED</span>
                        </td>
                        <td className="p-3">
                          <div className="w-16 h-2 bg-surface-variant">
                            <div
                              className="h-full bg-primary-container"
                              style={{ width: "40%" }}
                            ></div>
                          </div>
                        </td>
                      </tr>
                      <tr className="border-b border-outline-variant/30 hover:bg-surface-variant transition-colors cursor-pointer group">
                        <td className="p-3 text-primary">10.0.42.105</td>
                        <td className="p-3">db-01.internal.alpha</td>
                        <td className="p-3 text-on-surface-variant">
                          DISCOVERED
                        </td>
                        <td className="p-3">
                          <div className="w-16 h-2 bg-surface-variant">
                            <div
                              className="h-full bg-on-surface-variant"
                              style={{ width: "10%" }}
                            ></div>
                          </div>
                        </td>
                      </tr>
                      <tr className="border-b border-outline-variant/30 bg-error-container/5 hover:bg-error-container/10 transition-colors cursor-pointer group">
                        <td className="p-3 text-error group-hover:glow-red">
                          10.0.1.5
                        </td>
                        <td className="p-3">vault.alpha-corp.com</td>
                        <td className="p-3 text-error">VULNERABLE</td>
                        <td className="p-3">
                          <div className="w-16 h-2 bg-surface-variant">
                            <div
                              className="h-full bg-error"
                              style={{ width: "95%" }}
                            ></div>
                          </div>
                        </td>
                      </tr>
                      <tr className="border-b border-outline-variant/30 hover:bg-surface-variant transition-colors cursor-pointer group">
                        <td className="p-3 text-primary">44.201.12.8</td>
                        <td className="p-3">prod-lb.alpha-corp.com</td>
                        <td className="p-3 text-primary-container">PROBED</td>
                        <td className="p-3">
                          <div className="w-16 h-2 bg-surface-variant">
                            <div
                              className="h-full bg-primary-container"
                              style={{ width: "30%" }}
                            ></div>
                          </div>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* BOTTOM TERMINAL */}
          <div className="h-72 bg-black border-t border-outline-variant flex flex-col shrink-0">
            <div className="flex h-10 bg-surface-container-low border-b border-outline-variant">
              <button
                className={`px-6 border-r border-outline-variant font-label-caps text-[10px] transition-colors ${
                  terminalTab === "audit"
                    ? "bg-black text-primary"
                    : "text-on-surface-variant hover:text-primary"
                }`}
                onClick={() => setTerminalTab("audit")}
              >
                SYSTEM AUDIT
              </button>
              <button
                className={`px-6 border-r border-outline-variant font-label-caps text-[10px] transition-colors ${
                  terminalTab === "reasoning"
                    ? "bg-black text-primary"
                    : "text-on-surface-variant hover:text-primary"
                }`}
                onClick={() => setTerminalTab("reasoning")}
              >
                AGENT REASONING
              </button>
            </div>

            {/* TERMINAL CONTENT: SYSTEM AUDIT */}
            {terminalTab === "audit" && (
              <div
                className="flex-1 p-4 font-code-sm text-code-sm overflow-y-auto terminal-scroll space-y-1"
                ref={terminalRef}
              >
                <div className="flex gap-4">
                  <span className="text-on-surface-variant">[09:42:01]</span>{" "}
                  <span className="text-primary-container">[SYS]</span> SYSCALL
                  EXECVE: /usr/bin/python3
                </div>
                <div className="flex gap-4">
                  <span className="text-on-surface-variant">[09:42:15]</span>{" "}
                  <span className="text-primary-container">[SYS]</span> PROCESS
                  FORK: Child 8821 spawned.
                </div>
                <div className="flex gap-4">
                  <span className="text-on-surface-variant">[09:43:44]</span>{" "}
                  <span className="text-error">[AUDIT]</span> Unauthorized memory
                  access attempt at 0x7fff...
                </div>
                <div className="flex gap-4">
                  <span className="text-on-surface-variant">[09:44:02]</span>{" "}
                  <span className="text-secondary-fixed">[AUDIT]</span> Kernel
                  integrity check: PASSED.
                </div>
                <div className="flex gap-4">
                  <span className="text-on-surface-variant">[09:45:10]</span>{" "}
                  <span className="text-primary-container">[SYS]</span> Socket
                  opened: 0.0.0.0:4444 (TCP)
                </div>
              </div>
            )}

            {/* TERMINAL CONTENT: AGENT REASONING */}
            {terminalTab === "reasoning" && (
              <div
                className="flex-1 p-4 font-code-sm text-code-sm overflow-y-auto terminal-scroll space-y-2"
                ref={terminalRef}
              >
                <div className="flex gap-3">
                  <span className="text-primary-fixed-dim shrink-0">
                    AGENT_01:
                  </span>
                  <span className="text-on-surface italic">
                    "Analyzing attack surface... Cloudflare WAF detected.
                    Scanning for misconfigured origin IPs."
                  </span>
                </div>
                <div className="flex gap-3">
                  <span className="text-primary-fixed-dim shrink-0">
                    THINKING:
                  </span>
                  <span className="text-on-surface-variant text-[11px]">
                    IF bypass_prob &gt; 0.6 THEN execute exploit_module_v3 ELSE
                    escalate_to_operator
                  </span>
                </div>
                <div className="flex gap-3">
                  <span className="text-primary-fixed-dim shrink-0">
                    DECISION:
                  </span>
                  <span className="text-primary-container">
                    Proceeding with SSRF payload injection. Probability of
                    success: 72%.
                  </span>
                </div>
              </div>
            )}

            <div className="h-10 bg-surface-container-low border-t border-outline-variant px-4 flex items-center gap-3">
              <span className="text-primary-container font-code-sm">&gt;</span>
              <input
                className="bg-transparent border-none outline-none focus:ring-0 flex-1 font-code-sm text-primary p-0 placeholder-primary/30"
                placeholder="AWAITING COMMAND_"
                type="text"
              />
              <div className="w-2 h-4 bg-primary-container cursor-blink"></div>
            </div>
          </div>
        </main>

        {/* RIGHT SIDEBAR */}
        <aside className="w-80 bg-surface border-l border-outline-variant shrink-0 flex flex-col overflow-y-auto p-gutter relative z-20">
          {/* WAF INTELLIGENCE */}
          <div className="mb-8">
            <div className="font-label-caps text-label-caps text-on-surface-variant mb-4 border-b border-outline-variant pb-1 flex items-center justify-between">
              WAF INTELLIGENCE
              <span className="material-symbols-outlined text-[14px]">
                security
              </span>
            </div>
            <div className="space-y-3">
              {/* Provider 1 */}
              <div className="bg-surface-container p-3 border border-outline-variant hover:border-primary-container/50 transition-colors cursor-default">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-label-caps text-[10px] text-primary">
                    CLOUDFLARE V3
                  </span>
                  <span className="font-label-caps text-[9px] text-primary px-1 bg-primary/10">
                    THREAT: MED
                  </span>
                </div>
                <div className="flex justify-between items-end mb-1">
                  <span className="font-code-sm text-[10px] text-on-surface-variant uppercase">
                    Bypass Chance
                  </span>
                  <span className="font-label-caps text-[10px] text-primary-container">
                    65%
                  </span>
                </div>
                <div className="h-1 bg-surface-variant">
                  <div
                    className="h-full bg-primary-container glow-cyan"
                    style={{ width: "65%" }}
                  ></div>
                </div>
              </div>

              {/* Provider 2 */}
              <div className="bg-surface-container p-3 border border-outline-variant hover:border-primary-container/50 transition-colors cursor-default">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-label-caps text-[10px] text-on-surface-variant">
                    AWS WAF
                  </span>
                  <span className="font-label-caps text-[9px] text-error px-1 bg-error/10">
                    THREAT: HIGH
                  </span>
                </div>
                <div className="flex justify-between items-end mb-1">
                  <span className="font-code-sm text-[10px] text-on-surface-variant uppercase">
                    Bypass Chance
                  </span>
                  <span className="font-label-caps text-[10px] text-on-surface-variant">
                    12%
                  </span>
                </div>
                <div className="h-1 bg-surface-variant">
                  <div
                    className="h-full bg-error glow-red"
                    style={{ width: "12%" }}
                  ></div>
                </div>
              </div>

              {/* Provider 3 */}
              <div className="bg-surface-container p-3 border border-outline-variant hover:border-primary-container/50 transition-colors cursor-default">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-label-caps text-[10px] text-on-surface-variant">
                    AKAMAI KOANA
                  </span>
                  <span className="font-label-caps text-[9px] text-secondary-container px-1 bg-secondary-container/10">
                    THREAT: LOW
                  </span>
                </div>
                <div className="flex justify-between items-end mb-1">
                  <span className="font-code-sm text-[10px] text-on-surface-variant uppercase">
                    Bypass Chance
                  </span>
                  <span className="font-label-caps text-[10px] text-secondary-container">
                    89%
                  </span>
                </div>
                <div className="h-1 bg-surface-variant">
                  <div
                    className="h-full bg-secondary-container glow-green"
                    style={{ width: "89%" }}
                  ></div>
                </div>
              </div>
            </div>
          </div>

          {/* CREDENTIAL VAULT */}
          <div className="mb-8">
            <div className="font-label-caps text-label-caps text-on-surface-variant mb-4 border-b border-outline-variant pb-1 flex items-center justify-between">
              CREDENTIAL VAULT
              <span className="material-symbols-outlined text-[14px]">
                lock_open
              </span>
            </div>
            <div className="space-y-2">
              <div className="p-2 border border-outline-variant bg-black/40 flex items-center justify-between group cursor-pointer hover:border-primary-fixed transition-all hover:bg-surface-container">
                <span className="font-code-sm text-[11px] text-on-surface-variant truncate mr-2">
                  root: $argon2i$v=19$m=4096...
                </span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary-fixed opacity-0 group-hover:opacity-100 transition-all">
                  content_copy
                </span>
              </div>
              <div className="p-2 border border-outline-variant bg-black/40 flex items-center justify-between group cursor-pointer hover:border-primary-fixed transition-all hover:bg-surface-container">
                <span className="font-code-sm text-[11px] text-on-surface-variant truncate mr-2">
                  db_admin: $sha512$512$t=2...
                </span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary-fixed opacity-0 group-hover:opacity-100 transition-all">
                  content_copy
                </span>
              </div>
              <div className="p-2 border border-outline-variant bg-black/40 flex items-center justify-between group cursor-pointer hover:border-primary-fixed transition-all hover:bg-surface-container">
                <span className="font-code-sm text-[11px] text-on-surface-variant truncate mr-2">
                  sys_dev: $pbkdf2$s2id$612...
                </span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary-fixed opacity-0 group-hover:opacity-100 transition-all">
                  content_copy
                </span>
              </div>
              <div className="p-2 border border-outline-variant bg-black/40 flex items-center justify-between group cursor-pointer hover:border-primary-fixed transition-all hover:bg-surface-container">
                <span className="font-code-sm text-[11px] text-on-surface-variant truncate mr-2">
                  svc_web: cleartext:P@ssw0rd1
                </span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary-fixed opacity-0 group-hover:opacity-100 transition-all">
                  content_copy
                </span>
              </div>
              <div className="p-2 border border-outline-variant bg-black/40 flex items-center justify-between group cursor-pointer hover:border-primary-fixed transition-all hover:bg-surface-container">
                <span className="font-code-sm text-[11px] text-on-surface-variant truncate mr-2">
                  infra_ops: cert_thumb:7ea2...
                </span>
                <span className="material-symbols-outlined text-[16px] text-on-surface-variant group-hover:text-primary-fixed opacity-0 group-hover:opacity-100 transition-all">
                  content_copy
                </span>
              </div>
            </div>
          </div>

          <div className="mt-auto">
            <div className="border border-outline-variant bg-surface-container-low p-4">
              <div className="font-label-caps text-[9px] text-on-surface-variant mb-2">
                LIVE FEED // NETWORK UPTIME
              </div>
              <div className="flex items-end gap-1 h-12">
                <div className="w-full bg-primary-container/20 h-4 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-6 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-3 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-8 hover:h-10 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-5 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-7 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container/20 h-6 hover:h-8 transition-all hover:bg-primary-container"></div>
                <div className="w-full bg-primary-container h-8 animate-pulse"></div>
              </div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
