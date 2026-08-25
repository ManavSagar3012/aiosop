import React from 'react';

/**
 * Base skeleton element with shimmer animation.
 */
export const Skeleton: React.FC<{
  width?: string | number;
  height?: string | number;
  borderRadius?: string;
  className?: string;
  style?: React.CSSProperties;
}> = ({ width, height, borderRadius, className = '', style }) => (
  <div
    className={`skeleton ${className}`}
    style={{
      width,
      height,
      borderRadius: borderRadius || 'var(--radius-sm)',
      ...style,
    }}
  />
);

/**
 * Skeleton for a StatTile (KPI card).
 */
export const StatTileSkeleton: React.FC<{ delay?: number }> = ({ delay = 0 }) => (
  <div
    className="card"
    style={{
      padding: 20,
      animationDelay: `${delay}ms`,
    }}
  >
    <div className="flex items-start justify-between mb-3">
      <Skeleton width={80} height={10} />
      <Skeleton width={28} height={28} borderRadius="var(--radius-md)" />
    </div>
    <Skeleton width={60} height={32} style={{ marginBottom: 8 }} />
    <Skeleton width={120} height={10} />
  </div>
);

/**
 * Skeleton for a Card with content blocks.
 */
export const CardSkeleton: React.FC<{
  rows?: number;
  title?: boolean;
}> = ({ rows = 3, title = true }) => (
  <div className="card" style={{ padding: 20 }}>
    {title && (
      <div style={{ marginBottom: 16 }}>
        <Skeleton width={140} height={12} style={{ marginBottom: 4 }} />
        <Skeleton width={200} height={10} />
      </div>
    )}
    <div className="flex flex-col" style={{ gap: 12 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <Skeleton width={8} height={8} borderRadius="50%" />
          <Skeleton width={`${70 + Math.random() * 30}%`} height={14} />
        </div>
      ))}
    </div>
  </div>
);

/**
 * Skeleton for a DataTable.
 */
export const TableSkeleton: React.FC<{
  columns?: number;
  rows?: number;
}> = ({ columns = 4, rows = 5 }) => (
  <div style={{ padding: 20 }}>
    {/* Header */}
    <div
      style={{
        display: 'flex',
        gap: 16,
        padding: '10px 0',
        borderBottom: '1px solid var(--border)',
        marginBottom: 8,
      }}
    >
      {Array.from({ length: columns }).map((_, i) => (
        <Skeleton key={i} width={80} height={10} />
      ))}
    </div>
    {/* Rows */}
    {Array.from({ length: rows }).map((_, rowIdx) => (
      <div
        key={rowIdx}
        style={{
          display: 'flex',
          gap: 16,
          padding: '10px 0',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        {Array.from({ length: columns }).map((_, colIdx) => (
          <Skeleton
            key={colIdx}
            width={`${50 + Math.random() * 50}%`}
            height={14}
          />
        ))}
      </div>
    ))}
  </div>
);

/**
 * Skeleton for a chart area.
 */
export const ChartSkeleton: React.FC<{
  height?: number;
}> = ({ height = 220 }) => (
  <div
    style={{
      height,
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'flex-end',
      gap: 4,
      padding: '0 16px',
    }}
  >
    {Array.from({ length: 5 }).map((_, i) => (
      <div key={i} style={{ display: 'flex', alignItems: 'flex-end', gap: 4, flex: 1 }}>
        <Skeleton width={40} height={10} />
        <Skeleton
          width={`${20 + Math.random() * 60}%`}
          height="100%"
          borderRadius="2px 2px 0 0"
        />
      </div>
    ))}
  </div>
);

/**
 * Full-page loading state with optional message.
 */
export const PageSkeleton: React.FC<{
  message?: string;
}> = ({ message = 'Loading...' }) => (
  <div
    className="flex flex-col"
    style={{ gap: 20 }}
  >
    {/* Mission briefing skeleton */}
    <div className="card" style={{ padding: 20 }}>
      <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
        <Skeleton width={40} height={40} borderRadius="var(--radius-lg)" />
        <div style={{ flex: 1 }}>
          <Skeleton width={120} height={10} style={{ marginBottom: 8 }} />
          <Skeleton width={240} height={18} style={{ marginBottom: 4 }} />
          <Skeleton width={320} height={12} />
        </div>
      </div>
    </div>

    {/* KPI grid skeleton */}
    <div className="grid grid-cols-4" style={{ gap: 16 }}>
      {[0, 60, 120, 180].map(delay => (
        <StatTileSkeleton key={delay} delay={delay} />
      ))}
    </div>

    {/* Content skeleton */}
    <div className="grid grid-cols-3" style={{ gap: 16 }}>
      <div className="col-span-2">
        <CardSkeleton rows={4} />
      </div>
      <CardSkeleton rows={3} />
    </div>

    {/* Loading message */}
    {message && (
      <div
        className="flex items-center justify-center"
        style={{
          padding: 16,
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12,
          color: 'var(--text-tertiary)',
        }}
      >
        <div
          style={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: 'var(--accent)',
            animation: 'pulse-soft 2s infinite',
            marginRight: 8,
          }}
        />
        {message}
      </div>
    )}
  </div>
);
