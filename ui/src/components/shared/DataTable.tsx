import React from 'react';
import { EmptyState } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  align?: 'left' | 'right' | 'center';
  render?: (row: T) => React.ReactNode;
}

const alignClass = (a?: 'left' | 'right' | 'center') =>
  a === 'right' ? 'text-right' : a === 'center' ? 'text-center' : '';

export function DataTable<T>({
  columns, rows, rowKey, empty,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  empty?: React.ReactNode;
}) {
  return (
    <div className="overflow-y-auto custom-scrollbar -mx-2">
      <table className="w-full text-left font-code-sm text-code-sm">
        <thead className="sticky top-0 z-10">
          <tr className="text-on-surface-variant bg-surface-container-high">
            {columns.map((c) => (
              <th key={c.key} className={`px-3 py-2.5 font-label-caps text-label-xs uppercase ${alignClass(c.align)} ${c.width || ''}`}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)} className="border-b border-outline-variant/30 hover:bg-surface-container-high/60 transition-colors group">
              {columns.map((c) => (
                <td key={c.key} className={`px-3 py-2.5 ${alignClass(c.align)}`}>
                  {c.render ? c.render(row) : String((row as any)[c.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-3 py-16 text-center">
                {empty || <EmptyState message="No data yet." />}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
