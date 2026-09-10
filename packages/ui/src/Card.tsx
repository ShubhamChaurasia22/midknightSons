import React from 'react';

export interface CardProps {
  title?: string;
  subtitle?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  children,
  footer,
  className = '',
}) => {
  return (
    <div className={`shield-card ${className}`.trim()}>
      {(title || subtitle) && (
        <div className="shield-card-header">
          {title && <h3 className="shield-card-title">{title}</h3>}
          {subtitle && <p className="shield-card-subtitle">{subtitle}</p>}
        </div>
      )}
      <div className="shield-card-content">{children}</div>
      {footer && <div className="shield-card-footer">{footer}</div>}
    </div>
  );
};
