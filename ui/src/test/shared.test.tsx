import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatTile } from '../components/shared/StatTile';
import { StatusBadge } from '../components/shared/StatusBadge';
import { EmptyState } from '../components/shared/EmptyState';
import { ErrorState } from '../components/shared/ErrorState';
import { Skeleton } from '../components/shared/Skeleton';

describe('StatTile', () => {
  it('renders label and value', () => {
    render(<StatTile label="Verified" value={42} accent="primary" />);
    expect(screen.getByText('Verified')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('renders React node values', () => {
    render(<StatTile label="Agents" value={<span data-testid="v">7</span>} accent="secondary" />);
    expect(screen.getByTestId('v')).toHaveTextContent('7');
  });
});

describe('StatusBadge', () => {
  it('renders known status with mapped styling', () => {
    render(<StatusBadge value="verified" />);
    const el = screen.getByText(/verified/i);
    expect(el).toBeInTheDocument();
    expect(el.className).toContain('text-primary-fixed');
  });

  it('falls back safely for unknown severity', () => {
    render(<StatusBadge value="mystery" kind="severity" />);
    const el = screen.getByText(/mystery/i);
    expect(el.className).toContain('border-outline');
  });
});

describe('EmptyState / ErrorState', () => {
  it('shows message', () => {
    render(<EmptyState message="Nothing here yet" />);
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument();
  });

  it('ErrorState renders message', () => {
    render(<ErrorState message="Backend unreachable" />);
    expect(screen.getByText(/Backend unreachable/)).toBeInTheDocument();
  });
});

describe('Skeleton', () => {
  it('renders a pulse placeholder', () => {
    const { container } = render(<Skeleton className="h-10 w-10" />);
    expect(container.firstChild).toHaveClass('animate-pulse');
  });
});
