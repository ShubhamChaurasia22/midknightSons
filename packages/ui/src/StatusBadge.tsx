import React from 'react';

export type BadgeStatus = 'active' | 'warning' | 'error' | 'idle';

export interface StatusBadgeProps {
  status: BadgeStatus;
  label: string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, label, className = '' }) => {
  return (
    <span className={`shield-status-badge shield-status-badge-${status} ${className}`.trim()}>
      <span className="shield-status-dot" />
      <span>{label}</span>
    </span>
  );
};
