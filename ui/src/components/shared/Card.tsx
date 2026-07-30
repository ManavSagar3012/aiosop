import React from 'react';
import { Panel } from './Panel';

interface CardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  glow?: 'cyan' | 'red' | 'green' | 'none';
  action?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({ title, children, className = '', glow = 'none', action }) => (
  <Panel title={title} glow={glow} className={className} action={action}>{children}</Panel>
);
