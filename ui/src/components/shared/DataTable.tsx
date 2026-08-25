import React from 'react';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  align?: 'left' | 'right' | 'center';
  sortable?: boolean;
  render?: (row: T) => React.ReactNode;
}

const alignClass = (a?: 'left' | 'right' | 'center') =>
  a === 'right' ? 'text-right' : a === 'center' ? 'text-center' : '';

export function DataTable<T>({
  columns, rows, rowKey, empty, onRowClick,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  empty?: React.ReactNode;
  onRowClick?: (row: T) => void;
}) {
  return (
    <div className="overflow-y-auto custom-scrollbar">
      <table
        className="w-full text-left"
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12,
          borderCollapse: 'separate',
          borderSpacing: 0,
        }}
      >
        <thead>
          <tr
            style={{
              background: 'var(--surface-2)',
              borderBottom: '1px solid var(--border)',
            }}
          >
            {columns.map((c) => (
              <th
                key={c.key}
                className={`${alignClass(c.align)}`}
                style={{
                  padding: '10px 14px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                  color: 'var(--text-tertiary)',
                  borderBottom: '1px solid var(--border)',
                  position: 'sticky',
                  top: 0,
                  background: 'var(--surface-2)',
                  zIndex: 10,
                  ...(c.width ? { width: c.width } : {}),
                }}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => {
            const key = rowKey(row);
            return (
              <tr
                key={key || `row-${idx}`}
                onClick={() => onRowClick?.(row)}
                className={onRowClick ? 'cursor-pointer' : ''}
                style={{
                  borderBottom: '1px solid var(--border-subtle)',
                  transition: 'background var(--duration-fast)',
                  background: idx % 2 === 1 ? 'rgba(255,255,255,0.01)' : undefined,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-hover)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = idx % 2 === 1 ? 'rgba(255,255,255,0.01)' : undefined)}
              >
                {columns.map((c) => (
                  <td
                    key={String(c.key)}
                    className={`${alignClass(c.align)}`}
                    style={{ padding: '10px 14px', color: 'var(--text-primary)' }}
                  >
                    {c.render ? c.render(row) : String((row as any)[c.key] ?? '')}
                  </td>
                ))}
              </tr>
            );
          })}
          {rows.length === 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{ padding: '48px 14px', textAlign: 'center' }}
              >
                {empty || <EmptyState message="No data available" />}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
