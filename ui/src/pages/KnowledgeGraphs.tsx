import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Card } from '../components/shared/Card';
import { EmptyState } from '../components/shared/EmptyState';
import {
    ReactFlow,
    Background,
    Controls,
    MiniMap,
    useNodesState,
    useEdgesState,
    NodeMouseHandler,
    Panel,
    Handle,
    Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from 'dagre';
import {
  Server, Globe, ShieldAlert, Cloud, Activity,
  Box, FileJson, AlertTriangle, Search
} from 'lucide-react';
import { useIntelligenceStore } from '../store/useIntelligenceStore'
import { useToast } from '../hooks/useToast'

// React Flow sets node/edge colors as raw SVG/DOM style props (stroke=,
// fill=, background-color=), so a bare var(--x) string or Tailwind class
// will NOT resolve there — we need a resolved color STRING. Read the design
// tokens straight off the root element (single source of truth = styles.css)
// and fall back to the historical neon literals only if computed styles are
// unavailable (same pattern established in LearningAnalytics.tsx / Task 19).
const cssVar = (name: string, fallback: string) => {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
};


const GRAPH_FILTERS = {
  attack: ['Asset', 'Endpoint', 'Vulnerability', 'Exploit', 'Payload'],
  workflow: ['Workflow', 'Step', 'Transition', 'Intent', 'SemanticElement', 'Endpoint'],
  cloud: ['CloudResource', 'Asset', 'Endpoint'],
  learning: ['State', 'OutcomeRecord', 'Endpoint']
};

// --- Custom Node Component ---
const CustomNode = ({ data }: any) => {
  const Icon = data.icon || Box;
  const isHighlighted = data.isHighlighted;
  
  return (
    <div className={`w-64 rounded-sm border bg-surface-container flex flex-col overflow-hidden shadow-lg transition-all hover:scale-105 ${data.borderClass} ${data.glowClass} ${isHighlighted ? 'ring-2 ring-primary-fixed !border-primary-fixed scale-110 z-50' : 'opacity-60'}`}>
      <Handle type="target" position={Position.Top} className="w-3 h-1 !bg-outline-variant !rounded-none !border-none" />
      
      <div className={`px-3 py-2 border-b flex items-center justify-between ${data.headerClass} ${data.borderClass}`}>
         <div className="flex items-center gap-2">
            <Icon size={14} className={data.iconClass} />
            <span className={`font-label-caps text-[10px] tracking-widest ${data.iconClass}`}>{data.type}</span>
         </div>
         {data.confidence > 0 && (
            <span className="font-code-sm text-label-xs opacity-70">{(data.confidence * 100).toFixed(0)}%</span>
         )}
      </div>
      
      <div className="p-4 font-code-sm text-[11px] text-on-surface break-all line-clamp-3 leading-relaxed min-h-[60px] flex items-center">
         {data.label}
      </div>

      <Handle type="source" position={Position.Bottom} className="w-3 h-1 !bg-outline-variant !rounded-none !border-none" />
    </div>
  );
};

const nodeTypes = { custom: CustomNode };

export const KnowledgeGraphs: React.FC = () => {
  const [activeGraph, setActiveGraph] = useState<'attack' | 'workflow' | 'cloud' | 'learning'>('attack');
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([]);
  const { graphData } = useIntelligenceStore();
  const { addToast } = useToast();
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [isRelayouting, setIsRelayouting] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // React Flow color tokens — identical hexes as before, now sourced from styles.css.
  const flowColors = useMemo(() => ({
    edgeStroke:     cssVar('--on-surface-variant', '#baccb0'),
    edgeLabelFill:  cssVar('--on-surface', '#e5e2e3'),
    edgeLabelBg:    cssVar('--surface-container-low', '#0a0a0b'),
    bgGrid:         cssVar('--surface-container-high', '#1a1a1d'),
    vuln:           cssVar('--error', '#ff3131'),
    cloudResource:  cssVar('--primary', '#39ff14'),
    asset:          cssVar('--secondary', '#00f1fd'),
    miniMapDefault: cssVar('--surface-container-highest', '#2a2a2d'),
  }), []);

  // 1. Graph Highlighting Logic
  const highlightedNodes = useMemo(() => {
     if (!searchQuery) return new Set();
     const query = searchQuery.toLowerCase();
     return new Set(
        (graphData.nodes || [])
           .filter(n => 
              n.id.toLowerCase().includes(query) || 
              (n.properties?.name || '').toLowerCase().includes(query) ||
              (n.properties?.url || '').toLowerCase().includes(query)
           )
           .map(n => n.id)
     );
  }, [searchQuery, graphData]);

  // Filter and layout nodes
  useEffect(() => {
    if (!graphData.nodes || graphData.nodes.length === 0) return;
    setIsRelayouting(true);

    const allowedLabels = GRAPH_FILTERS[activeGraph];
    
    const filteredNodes = (graphData.nodes || []).filter(n => {
        if (!n.labels) return true; 
        return n.labels.some((l: string) => allowedLabels.includes(l));
    });

    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = (graphData.edges || []).filter(e => nodeIds.has(e.from) && nodeIds.has(e.to));

    // Smart Layout Engine
    // 1. Identify connected vs disconnected nodes
    const connectedNodeIds = new Set<string>();
    filteredEdges.forEach(e => {
        connectedNodeIds.add(e.from);
        connectedNodeIds.add(e.to);
    });

    const connectedNodes = filteredNodes.filter(n => connectedNodeIds.has(n.id));
    const disconnectedNodes = filteredNodes.filter(n => !connectedNodeIds.has(n.id));

    const NODE_WIDTH = 256;
    const NODE_HEIGHT = 100;

    // 2. Layout connected nodes with Dagre
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));
    dagreGraph.setGraph({ rankdir: 'TB', ranksep: 100, nodesep: 60 });

    connectedNodes.forEach(n => {
        dagreGraph.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }); 
    });

    filteredEdges.forEach(e => {
        dagreGraph.setEdge(e.from, e.to);
    });

    dagre.layout(dagreGraph);

    // 3. Layout disconnected nodes in a grid
    let gridStartY = 0;
    if (connectedNodes.length > 0) {
        const maxY = Math.max(0, ...connectedNodes.map(n => dagreGraph.node(n.id)?.y || 0));
        gridStartY = maxY + 200;
    }

    const GRID_COLS = Math.min(6, Math.max(3, Math.ceil(Math.sqrt(disconnectedNodes.length))));
    const GRID_X_SPACING = NODE_WIDTH + 40;
    const GRID_Y_SPACING = NODE_HEIGHT + 40;

    const mappedNodes = filteredNodes.map((n: any) => {
        const type = n.labels?.[0] || 'Unknown';
        const labelText = n.properties?.name || n.properties?.value || n.properties?.url || n.id;
        const confidence = n.properties?.confidence || 0;
        const isHighlighted = highlightedNodes.has(n.id) || highlightedNodes.size === 0;

        let icon = Box;
        let borderClass = 'border-outline-variant';
        let headerClass = 'bg-black/40';
        let iconClass = 'text-on-surface-variant';
        let glowClass = '';

        if (type === 'Asset') {
            icon = Server;
            borderClass = 'border-secondary/30';
            iconClass = 'text-secondary';
        } else if (type === 'Endpoint') {
            icon = Globe;
            borderClass = 'border-on-surface-variant/30';
            iconClass = 'text-on-surface-variant';
        } else if (type === 'Vulnerability') {
            icon = ShieldAlert;
            borderClass = 'border-error/50';
            headerClass = 'bg-error/10';
            iconClass = 'text-error';
            glowClass = 'glow-red';
        } else if (type === 'CloudResource') {
            icon = Cloud;
            borderClass = 'border-primary-fixed/50';
            headerClass = 'bg-primary-fixed/10';
            iconClass = 'text-primary-fixed';
            glowClass = 'glow-cyan';
        } else if (type === 'Workflow') {
            icon = Activity;
            borderClass = 'border-secondary-container/50';
            iconClass = 'text-secondary-container';
        } else if (type === 'SemanticElement') {
            icon = FileJson;
            iconClass = 'text-primary';
        } else if (type === 'CriticalOperation') {
            icon = AlertTriangle;
            borderClass = 'border-error/80';
            headerClass = 'bg-error/20';
            iconClass = 'text-error';
            glowClass = 'glow-red';
        }

        // Apply Layout Positions
        let pos = { x: 0, y: 0 };
        if (connectedNodeIds.has(n.id)) {
            const dNode = dagreGraph.node(n.id);
            pos = { x: (dNode?.x || 0) - NODE_WIDTH / 2, y: (dNode?.y || 0) - NODE_HEIGHT / 2 };
        } else {
            const idx = disconnectedNodes.findIndex(dn => dn.id === n.id);
            pos = {
                x: (idx % GRID_COLS) * GRID_X_SPACING,
                y: gridStartY + Math.floor(idx / GRID_COLS) * GRID_Y_SPACING
            };
        }

        return {
            id: n.id,
            position: pos,
            type: 'custom',
            data: { 
                label: labelText, 
                type: type?.toUpperCase() || 'UNKNOWN',
                icon,
                borderClass,
                headerClass,
                iconClass,
                glowClass,
                confidence,
                isHighlighted
            },
            __raw: n
        };
    });

    const mappedEdges = filteredEdges.map((e: any) => {
        return {
            id: e.id || `edge-${e.from}-${e.to}-${Math.random()}`,
            source: e.from,
            target: e.to,
            label: e.type,
            animated: true,
            style: { stroke: flowColors.edgeStroke, strokeWidth: 1.5, opacity: 0.4 },
            labelStyle: { fill: flowColors.edgeLabelFill, fontSize: 10, fontFamily: 'JetBrains Mono' },
            labelBgStyle: { fill: flowColors.edgeLabelBg, fillOpacity: 0.9 },
            labelBgPadding: [6, 4],
            labelBgBorderRadius: 2
        };
    });

    setNodes(mappedNodes);
    setEdges(mappedEdges);
    
    // Tiny delay to allow ReactFlow to render before we hide the loading screen
    setTimeout(() => setIsRelayouting(false), 100);
  }, [graphData, activeGraph, setNodes, setEdges, highlightedNodes, flowColors]);

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
      setSelectedNode((node as any).__raw);
  }, []);

  const inspectorData = useMemo(() => {
      if (!selectedNode) return null;
      return {
          title: selectedNode.labels?.[0] || 'Node',
          label: selectedNode.properties?.title || selectedNode.properties?.name || selectedNode.properties?.value || selectedNode.properties?.url || selectedNode.id,
          description: selectedNode.properties?.description || null,
          confidence: selectedNode.properties?.confidence || 0,
          status: selectedNode.properties?.status || 'DISCOVERED',
          isVuln: selectedNode.labels?.includes('Vulnerability')
      };
  }, [selectedNode]);

  return (
    <div className="flex flex-col h-full gap-6">
      <div className="flex gap-4 items-center">
        {['attack', 'workflow', 'cloud', 'learning'].map(g => (
          <button
            key={g}
            onClick={() => setActiveGraph(g as any)}
            className={`px-8 py-2.5 font-label-caps text-[11px] border transition-all ${
              activeGraph === g 
                ? 'bg-primary-container/10 border-primary-fixed text-primary-fixed glow-cyan shadow-[inset_0_0_10px_rgba(57,255,20,0.1)]' 
                : 'bg-surface-container border-outline-variant text-on-surface-variant hover:bg-surface-variant hover:text-on-surface'
            }`}
          >
            {g?.toUpperCase()} GRAPH
          </button>
        ))}
        <div className="ml-auto text-on-surface-variant font-code-sm text-[11px] bg-black px-4 py-2 border border-outline-variant">
           <span className="text-primary">{nodes.length}</span> NODES | <span className="text-secondary">{edges.length}</span> EDGES
        </div>
      </div>

      <div className="flex-1 min-h-0 bg-surface border border-outline-variant relative overflow-hidden terminal-grid rounded-sm">
        {isRelayouting ? (
           <div className="absolute inset-0 flex flex-col items-center justify-center text-primary-fixed font-code-sm text-code-sm bg-black/80 z-50 backdrop-blur-sm">
              <Activity className="animate-spin mb-4" size={32} />
              CALCULATING HIERARCHICAL LAYOUT...
           </div>
        ) : nodes.length === 0 ? (
           <div className="absolute inset-0 flex items-center justify-center">
              <EmptyState
                 message="No nodes in this graph view"
                 hint="Awaiting knowledge graph ingestion for this engagement"
                 icon={<Box size={28} />}
              />
           </div>
        ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              colorMode="dark"
              fitView
              minZoom={0.05}
              maxZoom={1.5}
            >
              <Background color={flowColors.bgGrid} gap={30} size={1} className="opacity-0" />
              <Controls className="bg-surface-container border-outline-variant text-on-surface fill-on-surface rounded-none shadow-xl" />
              <MiniMap
                 className="bg-surface-container border border-outline-variant rounded-none shadow-xl"
                 nodeColor={(n: any) => {
                    if (n.data?.type === 'VULNERABILITY') return flowColors.vuln;
                    if (n.data?.type === 'CLOUDRESOURCE') return flowColors.cloudResource;
                    if (n.data?.type === 'ASSET') return flowColors.asset;
                    return flowColors.miniMapDefault;
                 }}
                 maskColor="rgba(0, 0, 0, 0.7)"
              />

              <Panel position="top-left" className="ml-4 mt-4 w-72">
                 <div className="bg-surface-container border border-outline-variant p-2 shadow-2xl">
                    <div className="flex items-center gap-3 bg-black/40 border border-outline-variant px-3 py-2">
                       <Search size={14} className="text-on-surface-variant" />
                       <input 
                          type="text" 
                          placeholder="SEARCH GRAPH..." 
                          value={searchQuery}
                          onChange={(e) => setSearchQuery(e.target.value)}
                          className="bg-transparent border-none outline-none font-code-sm text-[11px] text-primary w-full placeholder:text-on-surface-variant/30"
                       />
                    </div>
                 </div>
              </Panel>
              
              <Panel position="top-right" className="w-80 mt-4 mr-4">
                 <Card title="Graph Inspector" glow={inspectorData?.isVuln ? 'red' : 'cyan'}>
                    {inspectorData ? (
                       <div className="font-code-sm text-[11px] space-y-5">
                          <div className="bg-black/40 p-3 border border-outline-variant">
                             <div className="text-on-surface-variant text-label-xs mb-2 uppercase tracking-widest border-b border-outline-variant/30 pb-1">{inspectorData.title}</div>
                             <div className="text-primary break-all leading-relaxed" title={inspectorData.label}>{inspectorData.label}</div>
                          </div>
                          
                          {inspectorData.description && (
                             <div className="bg-black/40 p-3 border border-outline-variant">
                                <div className="text-on-surface-variant text-label-xs mb-2 uppercase tracking-widest border-b border-outline-variant/30 pb-1">Description</div>
                                <div className="text-on-surface leading-relaxed text-[10px] break-words">{inspectorData.description}</div>
                             </div>
                          )}
                          
                          {inspectorData.confidence > 0 && (
                              <div>
                                 <div className="text-on-surface-variant text-label-xs mb-2 uppercase tracking-widest">Confidence</div>
                                 <div className="flex items-center gap-3">
                                    <div className="flex-1 h-1.5 bg-surface-variant">
                                       <div className={`h-full ${inspectorData.isVuln ? 'bg-error glow-red' : 'bg-primary-fixed glow-cyan'}`} style={{ width: `${inspectorData.confidence * 100}%` }}></div>
                                    </div>
                                    <span className={inspectorData.isVuln ? 'text-error' : 'text-primary-fixed'}>{(inspectorData.confidence * 100).toFixed(0)}%</span>
                                 </div>
                              </div>
                          )}
                          
                          <div className="flex justify-between items-center bg-black/40 p-3 border border-outline-variant">
                             <div className="text-on-surface-variant text-label-xs uppercase tracking-widest">Status</div>
                             <div className={`${inspectorData.isVuln ? 'text-error glow-red' : 'text-primary-fixed glow-cyan'} font-bold tracking-widest px-2 py-0.5 border ${inspectorData.isVuln ? 'border-error/30' : 'border-primary-fixed/30'}`}>
                                {inspectorData.status?.toUpperCase()}
                             </div>
                          </div>
                          
                          <button 
                            onClick={() => addToast(`Evidence timeline for ${inspectorData.label} not yet implemented`, "warning")}
                            className="w-full py-3 bg-surface-container-high border border-outline-variant text-on-surface font-label-caps text-[10px] hover:bg-surface-variant transition-all mt-4"
                          >
                             VIEW EVIDENCE TIMELINE
                          </button>
                       </div>
                    ) : (
                        <div className="text-on-surface-variant text-[11px] font-code-sm italic text-center py-8 opacity-60">
                            Select a node in the graph to inspect properties.
                        </div>
                    )}
                 </Card>
              </Panel>
            </ReactFlow>
        )}
      </div>
    </div>
  );
};
