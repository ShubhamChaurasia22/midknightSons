import React, { useState, useEffect } from 'react';
import { Card, StatusBadge, Toggle } from '@shield/ui';
import { EXTENSION_NAME, EXTENSION_VERSION, STORAGE_KEYS } from '@shield/shared';
import '@shield/ui/styles.css';
import './options.css';

export const Options: React.FC = () => {
  const [enabled, setEnabled] = useState(true);

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get([STORAGE_KEYS.ENABLED], (res) => {
        if (res[STORAGE_KEYS.ENABLED] !== undefined) {
          setEnabled(Boolean(res[STORAGE_KEYS.ENABLED]));
        }
      });
    }
  }, []);

  const handleToggle = (nextState: boolean) => {
    setEnabled(nextState);
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ [STORAGE_KEYS.ENABLED]: nextState });
    }
  };

  return (
    <div className="options-container">
      <div className="options-header">
        <h1 className="options-title">{EXTENSION_NAME} Settings</h1>
        <StatusBadge status="active" label={`v${EXTENSION_VERSION} Scaffold`} />
      </div>

      <div className="options-grid">
        <Card title="General Configuration" subtitle="Phase 0 settings scaffold">
          <div className="options-row">
            <div>
              <div className="options-label">Shield Master Protection</div>
              <div className="options-description">
                Master switch for AI interaction protection.
              </div>
            </div>
            <Toggle checked={enabled} onChange={handleToggle} />
          </div>

          <div className="options-row">
            <div>
              <div className="options-label">Local-First Processing Policy</div>
              <div className="options-description">
                All data detection and transformations are performed on-device.
              </div>
            </div>
            <StatusBadge status="active" label="Enforced" />
          </div>
        </Card>

        <Card title="Future Engines Scaffold (M1+)" subtitle="Milestones roadmap">
          <div className="options-row">
            <div>
              <div className="options-label">PII & Secret Detection Engine</div>
              <div className="options-description">Scheduled for Milestone M1 (Core Engine).</div>
            </div>
            <StatusBadge status="idle" label="Planned M1" />
          </div>

          <div className="options-row">
            <div>
              <div className="options-label">Platform Adapters (ChatGPT, Claude, Gemini)</div>
              <div className="options-description">
                Scheduled for Milestone M2 (Platform Adapters).
              </div>
            </div>
            <StatusBadge status="idle" label="Planned M2" />
          </div>
        </Card>
      </div>
    </div>
  );
};
