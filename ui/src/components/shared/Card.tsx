import React from 'react';
import { Panel, PanelProps } from './Panel';

interface CardProps extends Omit<PanelProps, 'variant'> {}

export const Card: React.FC<CardProps> = ({ children, className = '', ...props }) => (
  <Panel className={className} {...props}>
    {children}
  </Panel>
);
