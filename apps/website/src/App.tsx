import React from 'react';
import { StatusBadge } from '@shield/ui';
import { EXTENSION_NAME, EXTENSION_VERSION } from '@shield/shared';
import '@shield/ui/styles.css';
import './index.css';

interface PlannedSection {
  title: string;
  description: string;
  milestone: string;
}

const PLANNED_SECTIONS: PlannedSection[] = [
  {
    title: 'Product Information',
    description: 'Overview of Shield privacy and security protection for AI web interfaces.',
    milestone: 'Planned M3',
  },
  {
    title: 'How It Works',
    description: 'Architecture and local-first execution pipeline breakdown.',
    milestone: 'Planned M3',
  },
  {
    title: 'Privacy',
    description: 'Local-first processing principles and zero-telemetry commitments.',
    milestone: 'Planned M3',
  },
  {
    title: 'Security',
    description: 'Security boundary threat models, client-side isolation, and disclosures.',
    milestone: 'Planned M3',
  },
  {
    title: 'Terms & Licensing',
    description: 'Usage policies and open-source licensing terms.',
    milestone: 'Planned M3',
  },
  {
    title: 'FAQ & Support',
    description: 'Frequently asked questions, troubleshooting guides, and issue tracker.',
    milestone: 'Planned M3',
  },
];

export const App: React.FC = () => {
  return (
    <div className="landing-container">
      <div className="hero">
        <div style={{ marginBottom: '16px' }}>
          <StatusBadge status="active" label={`v${EXTENSION_VERSION} Bootstrap`} />
        </div>
        <h1>{EXTENSION_NAME}</h1>
        <p>
          Privacy and security browser extension designed to protect sensitive information when
          interacting with AI platforms (ChatGPT, Claude, Gemini).
        </p>
        <div className="status-callout">Current State: Phase 0 — Repository Bootstrap Complete</div>
      </div>

      <div className="cards-grid">
        {PLANNED_SECTIONS.map((section) => (
          <div key={section.title} className="feature-placeholder">
            <h3>{section.title}</h3>
            <p>{section.description}</p>
            <span className="planned-tag">{section.milestone}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
