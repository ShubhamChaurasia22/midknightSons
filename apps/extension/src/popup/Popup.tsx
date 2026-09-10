import React, { useState, useEffect } from 'react';
import { Card, StatusBadge, Toggle, Button } from '@shield/ui';
import {
  EXTENSION_NAME,
  EXTENSION_VERSION,
  STORAGE_KEYS,
  createMessage,
  type ShieldMessage,
} from '@shield/shared';
import '@shield/ui/styles.css';
import './popup.css';

export const Popup: React.FC = () => {
  const [enabled, setEnabled] = useState(true);
  const [statusText, setStatusText] = useState('Checking service worker...');
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Load storage setting
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get([STORAGE_KEYS.ENABLED], (res) => {
        if (res[STORAGE_KEYS.ENABLED] !== undefined) {
          setEnabled(Boolean(res[STORAGE_KEYS.ENABLED]));
        }
      });

      // Send status query to service worker
      const queryMsg = createMessage('GET_STATUS', 'popup');
      chrome.runtime.sendMessage(queryMsg, (response: ShieldMessage | undefined) => {
        if (chrome.runtime.lastError) {
          setStatusText('Service worker idle / not connected');
          setIsConnected(false);
          return;
        }

        if (response && response.type === 'STATUS_RESPONSE') {
          setStatusText('Connected to Background Worker');
          setIsConnected(true);
        }
      });
    } else {
      setStatusText('Browser environment mock');
    }
  }, []);

  const handleToggle = (nextState: boolean) => {
    setEnabled(nextState);
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ [STORAGE_KEYS.ENABLED]: nextState });
    }
  };

  const openOptions = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open('options.html', '_blank');
    }
  };

  return (
    <div className="popup-container">
      <div className="popup-header">
        <h2 className="popup-title">
          <svg className="popup-shield-icon" viewBox="0 0 24 24">
            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" />
          </svg>
          {EXTENSION_NAME}
        </h2>
        <StatusBadge
          status={isConnected ? 'active' : 'idle'}
          label={isConnected ? 'Active' : 'Standby'}
        />
      </div>

      <Card title="Phase 0 — Repository Bootstrap" subtitle="Foundational development build">
        <p style={{ margin: '0 0 10px 0', fontSize: '13px', color: '#94a3b8' }}>
          Shield privacy & security foundation is running. Protection engines will be configured in
          Milestone M1.
        </p>

        <div className="popup-info-row">
          <span className="popup-info-label">Version</span>
          <span className="popup-info-value">v{EXTENSION_VERSION}</span>
        </div>

        <div className="popup-info-row">
          <span className="popup-info-label">Protection</span>
          <Toggle
            checked={enabled}
            onChange={handleToggle}
            label={enabled ? 'Enabled' : 'Disabled'}
          />
        </div>

        <div className="popup-info-row">
          <span className="popup-info-label">Worker Status</span>
          <span className="popup-info-value" style={{ fontSize: '11px' }}>
            {statusText}
          </span>
        </div>
      </Card>

      <div className="popup-actions">
        <Button variant="secondary" size="sm" onClick={openOptions} style={{ width: '100%' }}>
          Open Settings Scaffold
        </Button>
      </div>
    </div>
  );
};
