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
import { useIntelligenceStore } from '../store/useIntelligenceStore';

/**
 * Read a CSS custom property from the root element.
 * Falls back to the provided literal if the variable is empty or unavailable.
 */
const cssVar = (name: string, fallback: string) => {
  if (typeof document === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
};

const GRAPH_FILTERS: Record<string, string[]> = {
  attack: ['Asset', 'Endpoint', 'Vulnerability', 'Exploit', 'Payload', 'Primitive', 'Task'],
  workflow: ['Workflow', 'Step', 'Transition', 'Intent', 'SemanticElement', 'Endpoint', 'Task'],
  cloud: ['CloudResource', 'Asset', 'Endpoint'],
  learning: ['State', 'OutcomeRecord', 'Endpoint', 'Task'],
};

// ─── Custom Node ─────────────────────────────────────────────────────────────
const CustomNode = ({ data }: any) => {
  const Icon = data.icon || Box;

  return (
    <div
      style={{
        width: 256,
        background: 'var(--surface-1)',
        border: `1px solid ${data.borderColor || 'var(--border)'}`,
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
        boxShadow: 'var(--shadow-md)',
        transition: 'all 200ms ease',
      }}
    >
      <Handle type="target" position={Position.Top} />

      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '8px 12px',
          borderBottom: `1px solid ${data.borderColor || 'var(--border)'}`,
          background: data.headerBg || 'var(--surface-2)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon size={14} style={{ color: data.iconColor || 'var(--text-secondary)' }} />
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: data.iconColor || 'var(--text-secondary)',
            }}
          >
            {data.type}
          </span>
        </div>
        {data.confidence > 0 && (
          <span
            style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 10,
              color: 'var(--text-tertiary)',
            }}
          >
            {(data.confidence * 100).toFixed(0)}%
          </span>
        )}
      </div>

      {/* Label */}
      <div
        style={{
          padding: '12px',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11,
          color: 'var(--text-primary)',
          wordBreak: 'break-all',
          lineHeight: 1.5,
          minHeight: 60,
          display: 'flex',
          alignItems: 'center',
        }}
      >
        {data.label}
      </div>

      <Handle type="source" position={Position.Bottom} />
    </div>
  );
};

const nodeTypes = { custom: CustomNode };

// ─── Main Component ──────────────────────────────────────────────────────────
export const KnowledgeGraphs: React.FC = () => {
  const [activeGraph, setActiveGraph] = useState<'attack' | 'workflow' | 'cloud' | 'learning'>('attack');
  const [nodes, setNodes, onNodesChange] = useNodesState<any>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<any>([]);
  const { graphData } = useIntelligenceStore();
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [isRelayouting, setIsRelayouting] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Read CSS tokens at mount — these won't change without a theme toggle.
  const flowColors = useMemo(() => ({
    edgeStroke:    cssVar('--text-secondary', '#a0a3ab'),
    edgeLabelFill: cssVar('--text-primary', '#f0f0f2'),
    edgeLabelBg:   cssVar('--surface-1', '#111114'),
    bgGrid:        cssVar('--surface-2', '#18181b'),
    vuln:          cssVar('--danger', '#ef4444'),
    cloudResource: cssVar('--accent', '#39ff14'),
    asset:         cssVar('--interactive', '#00e5f0'),
    endpoint:      cssVar('--text-secondary', '#a0a3ab'),
    miniMap:       cssVar('--surface-3', '#1f1f23'),
  }), []);

  // ── Search highlighting ────────────────────────────────────────────
  const highlightedNodes = useMemo(() => {
    if (!searchQuery) return new Set<string>();
    const q = searchQuery.toLowerCase();
    return new Set(
      (graphData.nodes || [])
        .filter((n: any) =>
          n.id.toLowerCase().includes(q) ||
          (n.properties?.name || '').toLowerCase().includes(q) ||
          (n.properties?.url || '').toLowerCase().includes(q)
        )
        .map((n: any) => n.id)
    );
  }, [searchQuery, graphData]);

  // ── Layout & render ────────────────────────────────────────────────
  useEffect(() => {
    if (!graphData.nodes || graphData.nodes.length === 0) return;
    setIsRelayouting(true);

    const allowedLabels = GRAPH_FILTERS[activeGraph] || [];

    const filteredNodes = (graphData.nodes || []).filter((n: any) => {
      if (!n.labels || n.labels.length === 0) return true;
      return n.labels.some((l: string) => allowedLabels.includes(l));
    });

    const nodeIds = new Set(filteredNodes.map((n: any) => n.id));
    const filteredEdges = (graphData.edges || []).filter(
      (e: any) => nodeIds.has(e.from) && nodeIds.has(e.to)
    );

    // Identify connected vs disconnected nodes
    const connectedNodeIds = new Set<string>();
    filteredEdges.forEach((e: any) => {
      connectedNodeIds.add(e.from);
      connectedNodeIds.add(e.to);
    });

    const connectedNodes = filteredNodes.filter((n: any) => connectedNodeIds.has(n.id));
    const disconnectedNodes = filteredNodes.filter((n: any) => !connectedNodeIds.has(n.id));

    const NODE_WIDTH = 256;
    const NODE_HEIGHT = 100;

    // Layout connected nodes with Dagre
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));
    dagreGraph.setGraph({ rankdir: 'TB', ranksep: 100, nodesep: 60 });

    connectedNodes.forEach((n: any) => {
      dagreGraph.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
    });
    filteredEdges.forEach((e: any) => {
      dagreGraph.setEdge(e.from, e.to);
    });
    dagre.layout(dagreGraph);

    // Grid for disconnected nodes
    let gridStartY = 0;
    if (connectedNodes.length > 0) {
      const maxY = Math.max(0, ...connectedNodes.map((n: any) => dagreGraph.node(n.id)?.y || 0));
      gridStartY = maxY + 200;
    }

    const GRID_COLS = Math.min(6, Math.max(3, Math.ceil(Math.sqrt(disconnectedNodes.length))));
    const GRID_X_SPACING = NODE_WIDTH + 40;
    const GRID_Y_SPACING = NODE_HEIGHT + 40;

    // Map to ReactFlow nodes
    const mappedNodes = filteredNodes.map((n: any) => {
      const type = n.labels?.[0] || 'Unknown';
      const labelText = n.properties?.name || n.properties?.value || n.properties?.url || n.id;
      const confidence = n.properties?.confidence || 0;
      const isHighlighted = highlightedNodes.has(n.id) || highlightedNodes.size === 0;

      // Type-specific styling
      let icon = Box;
      let borderColor = 'var(--border)';
      let headerBg = 'var(--surface-2)';
      let iconColor = 'var(--text-secondary)';

      switch (type) {
        case 'Asset':
          icon = Server;
          borderColor = flowColors.asset;
          iconColor = flowColors.asset;
          break;
        case 'Endpoint':
          icon = Globe;
          borderColor = flowColors.endpoint;
          iconColor = flowColors.endpoint;
          break;
        case 'Vulnerability':
          icon = ShieldAlert;
          borderColor = flowColors.vuln;
          headerBg = 'var(--danger-bg)';
          iconColor = flowColors.vuln;
          break;
        case 'CloudResource':
          icon = Cloud;
          borderColor = flowColors.cloudResource;
          headerBg = 'var(--accent-bg)';
          iconColor = flowColors.cloudResource;
          break;
        case 'Workflow':
          icon = Activity;
          borderColor = 'var(--info-border)';
          iconColor = 'var(--info)';
          break;
        case 'SemanticElement':
          icon = FileJson;
          iconColor = 'var(--accent)';
          break;
        case 'CriticalOperation':
          icon = AlertTriangle;
          borderColor = flowColors.vuln;
          headerBg = 'var(--danger-bg)';
          iconColor = flowColors.vuln;
          break;
      }

      // Position
      let pos = { x: 0, y: 0 };
      if (connectedNodeIds.has(n.id)) {
        const dNode = dagreGraph.node(n.id);
        pos = {
          x: (dNode?.x || 0) - NODE_WIDTH / 2,
          y: (dNode?.y || 0) - NODE_HEIGHT / 2,
        };
      } else {
        const idx = disconnectedNodes.findIndex((dn: any) => dn.id === n.id);
        pos = {
          x: (idx % GRID_COLS) * GRID_X_SPACING,
          y: gridStartY + Math.floor(idx / GRID_COLS) * GRID_Y_SPACING,
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
          borderColor,
          headerBg,
          iconColor,
          confidence,
          isHighlighted,
        },
        style: isHighlighted
          ? { opacity: 1, zIndex: 10 }
          : { opacity: 0.5, zIndex: 1 },
        __raw: n,
      };
    });

    // Map to ReactFlow edges
    const mappedEdges = filteredEdges.map((e: any) => ({
      id: e.id || `edge-${e.from}-${e.to}-${Math.random().toString(36).slice(2, 8)}`,
      source: e.from,
      target: e.to,
      label: e.type,
      animated: true,
      style: {
        stroke: flowColors.edgeStroke,
        strokeWidth: 1.5,
        opacity: 0.4,
      },
      labelStyle: {
        fill: flowColors.edgeLabelFill,
        fontSize: 10,
        fontFamily: "'JetBrains Mono', monospace",
      },
      labelBgStyle: {
        fill: flowColors.edgeLabelBg,
        fillOpacity: 0.9,
      },
      labelBgPadding: [6, 4] as [number, number],
      labelBgBorderRadius: 4,
    }));

    setNodes(mappedNodes);
    setEdges(mappedEdges);

    setTimeout(() => setIsRelayouting(false), 150);
  }, [graphData, activeGraph, setNodes, setEdges, highlightedNodes, flowColors]);

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    setSelectedNode((node as any).__raw);
  }, []);

  const inspectorData = useMemo(() => {
    if (!selectedNode) return null;
    return {
      title: selectedNode.labels?.[0] || 'Node',
      label: selectedNode.properties?.name || selectedNode.properties?.value || selectedNode.properties?.url || selectedNode.id,
      confidence: selectedNode.properties?.confidence || 0,
      status: selectedNode.properties?.status || 'DISCOVERED',
      isVuln: selectedNode.labels?.includes('Vulnerability'),
    };
  }, [selectedNode]);

  const hasData = (graphData.nodes || []).length > 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: 16 }}>
      {/* Graph type tabs */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        {(['attack', 'workflow', 'cloud', 'learning'] as const).map(g => (
          <button
            key={g}
            onClick={() => setActiveGraph(g)}
            className={activeGraph === g ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm'}
          >
            {g.toUpperCase()} GRAPH
          </button>
        ))}
        <div
          style={{
            marginLeft: 'auto',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 11,
            color: 'var(--text-tertiary)',
            padding: '6px 12px',
            background: 'var(--surface-1)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
          }}
        >
          <span style={{ color: 'var(--accent)' }}>{nodes.length}</span> NODES |{' '}
          <span style={{ color: 'var(--interactive)' }}>{edges.length}</span> EDGES
        </div>
      </div>

      {/* Graph canvas */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          position: 'relative',
          background: 'var(--surface-1)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          overflow: 'hidden',
        }}
      >
        {isRelayouting ? (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--surface-overlay)',
              zIndex: 50,
            }}
          >
            <Activity
              size={32}
              style={{
                color: 'var(--accent)',
                animation: 'spin 1s linear infinite',
                marginBottom: 16,
              }}
            />
            <span
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 12,
                color: 'var(--accent)',
              }}
            >
              Calculating hierarchical layout...
            </span>
          </div>
        ) : !hasData ? (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <EmptyState
              message="No graph data available for this engagement"
              hint="Start a mission to populate the knowledge graph"
              icon={<Box size={28} />}
            />
          </div>
        ) : nodes.length === 0 ? (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <EmptyState
              message={`No ${activeGraph} graph nodes found`}
              hint="Try a different graph view or wait for data ingestion"
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
            fitView
            minZoom={0.05}
            maxZoom={1.5}
            style={{ width: '100%', height: '100%' }}
          >
            <Background
              color={flowColors.bgGrid}
              gap={30}
              size={1}
              style={{ opacity: 0.3 }}
            />
            <Controls />
            <MiniMap
              nodeColor={(n: any) => {
                if (n.data?.type === 'VULNERABILITY') return flowColors.vuln;
                if (n.data?.type === 'CLOUDRESOURCE') return flowColors.cloudResource;
                if (n.data?.type === 'ASSET') return flowColors.asset;
                return flowColors.miniMap;
              }}
              maskColor="rgba(0, 0, 0, 0.6)"
              style={{
                background: 'var(--surface-2)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
              }}
            />

            {/* Search panel */}
            <Panel position="top-left" style={{ marginLeft: 16, marginTop: 16 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  background: 'var(--surface-1)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                  padding: '8px 12px',
                  boxShadow: 'var(--shadow-lg)',
                }}
              >
                <Search size={14} style={{ color: 'var(--text-tertiary)', flexShrink: 0 }} />
                <input
                  type="text"
                  placeholder="Search graph nodes..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    outline: 'none',
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 12,
                    color: 'var(--text-primary)',
                    width: 200,
                  }}
                />
              </div>
            </Panel>

            {/* Inspector panel */}
            <Panel position="top-right" style={{ marginRight: 16, marginTop: 16, width: 280 }}>
              <Card
                title="Graph Inspector"
                accent={inspectorData?.isVuln ? 'danger' : 'info'}
              >
                {inspectorData ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                    <div
                      style={{
                        padding: 12,
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)',
                      }}
                    >
                      <div
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: '0.1em',
                          textTransform: 'uppercase',
                          color: 'var(--text-tertiary)',
                          marginBottom: 4,
                          paddingBottom: 4,
                          borderBottom: '1px solid var(--border)',
                        }}
                      >
                        {inspectorData.title}
                      </div>
                      <div
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 12,
                          color: 'var(--accent)',
                          wordBreak: 'break-all',
                          lineHeight: 1.5,
                        }}
                        title={inspectorData.label}
                      >
                        {inspectorData.label}
                      </div>
                    </div>

                    {inspectorData.confidence > 0 && (
                      <div>
                        <div
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: 9,
                            fontWeight: 700,
                            letterSpacing: '0.1em',
                            textTransform: 'uppercase',
                            color: 'var(--text-tertiary)',
                            marginBottom: 6,
                          }}
                        >
                          Confidence
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div className="progress" style={{ flex: 1 }}>
                            <div
                              className="progress-bar"
                              style={{
                                width: `${inspectorData.confidence * 100}%`,
                                background: inspectorData.isVuln ? 'var(--danger)' : 'var(--accent)',
                              }}
                            />
                          </div>
                          <span
                            style={{
                              fontFamily: "'JetBrains Mono', monospace",
                              fontSize: 11,
                              fontWeight: 600,
                              color: inspectorData.isVuln ? 'var(--danger)' : 'var(--accent)',
                              fontVariantNumeric: 'tabular-nums',
                            }}
                          >
                            {(inspectorData.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                    )}

                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '8px 12px',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-md)',
                      }}
                    >
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: '0.1em',
                          textTransform: 'uppercase',
                          color: 'var(--text-tertiary)',
                        }}
                      >
                        Status
                      </span>
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: 10,
                          fontWeight: 700,
                          letterSpacing: '0.08em',
                          color: inspectorData.isVuln ? 'var(--danger)' : 'var(--accent)',
                          padding: '2px 8px',
                          background: inspectorData.isVuln ? 'var(--danger-bg)' : 'var(--accent-bg)',
                          border: `1px solid ${inspectorData.isVuln ? 'var(--danger-border)' : 'var(--accent-border)'}`,
                          borderRadius: 'var(--radius-full)',
                        }}
                      >
                        {inspectorData.status?.toUpperCase()}
                      </span>
                    </div>
                  </div>
                ) : (
                  <div
                    style={{
                      textAlign: 'center',
                      padding: '32px 16px',
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      color: 'var(--text-tertiary)',
                      fontStyle: 'italic',
                    }}
                  >
                    Select a node to inspect its properties
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
