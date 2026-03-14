import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API = 'http://localhost:8002/api';

function severityClass(s) { return (s || 'low').toLowerCase(); }

function formatBytes(b) {
  if (b >= 1000000) return `${(b / 1000000).toFixed(1)} MB`;
  if (b >= 1000) return `${(b / 1000).toFixed(0)} KB`;
  return `${b} B`;
}

/* ─── Trust Methodology Section (static — real deduction logic from backend) ─── */
function TrustMethodology() {
  return (
    <div className="panel" style={{ marginBottom: 24 }}>
      <div className="panel-header">
        <div>
          <div className="panel-title">Trust Score Methodology</div>
          <div className="panel-subtitle">How the Ensemble Trust Score is computed from three independent signals</div>
        </div>
      </div>
      <div className="panel-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
          {/* Score Range */}
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>Score Range</div>
            <div style={{ fontSize: 13, color: '#64748b', lineHeight: 1.7 }}>
              <strong>0 &ndash; 100</strong> per device, per hourly window.<br />
              <span style={{ color: '#22c55e', fontWeight: 600 }}>100</span> = Fully Trusted &nbsp;|&nbsp;
              <span style={{ color: '#ef4444', fontWeight: 600 }}>0</span> = Likely Compromised<br />
              Represents <strong>real-time behavioural confidence</strong> based on network telemetry.
              <br /><br />
              Smoothing: <strong>Exponential Moving Average (alpha = 0.3)</strong> to prevent single-window noise from causing false alarms.
            </div>
          </div>
          {/* Risk Levels */}
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>Risk Severity Tiers</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { label: 'Low', range: '81 – 100', color: '#22c55e', bg: '#f0fdf4' },
                { label: 'Medium', range: '61 – 80', color: '#f59e0b', bg: '#fffbeb' },
                { label: 'High', range: '31 – 60', color: '#ef4444', bg: '#fef2f2' },
                { label: 'Critical', range: '0 – 30', color: '#991b1b', bg: '#fef2f2' },
              ].map(tier => (
                <div key={tier.label} style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '6px 12px', borderRadius: 6, background: tier.bg,
                  fontSize: 13,
                }}>
                  <span style={{
                    width: 10, height: 10, borderRadius: '50%',
                    background: tier.color, display: 'inline-block', flexShrink: 0,
                  }} />
                  <span style={{ fontWeight: 600, color: tier.color, width: 65 }}>{tier.label}</span>
                  <span style={{ color: '#64748b', fontVariantNumeric: 'tabular-nums' }}>{tier.range}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Deduction Logic */}
        <div style={{ marginTop: 24, borderTop: '1px solid #e2e8f0', paddingTop: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 12 }}>Deduction Logic &mdash; 3-Tier Signal Fusion</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
            {/* Tier 1 */}
            <div style={{ background: '#f8fafc', borderRadius: 10, padding: 16, border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#3b82f6', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
                Tier 1 — ML Anomaly
              </div>
              <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.7 }}>
                <strong>Isolation Forest</strong> (per device type)<br />
                Score: 0.0 (normal) &ndash; 1.0 (anomalous)<br />
                Deduction: <strong>score &times; 40 pts</strong> (max &minus;40)<br />
                <span style={{ fontSize: 11, color: '#94a3b8' }}>9 behavioural features &bull; StandardScaler normalized</span>
              </div>
            </div>
            {/* Tier 2 */}
            <div style={{ background: '#f8fafc', borderRadius: 10, padding: 16, border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
                Tier 2 — Statistical Drift
              </div>
              <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.7 }}>
                <strong>Z-Score Analysis</strong> vs learned baseline<br />
                DRIFT_NONE (z &lt; 1.5): <strong>0 pts</strong><br />
                DRIFT_MILD (1.5 &ndash; 3.0): <strong>&minus;10 pts</strong><br />
                DRIFT_STRONG (&gt; 3.0): <strong>&minus;20 pts</strong><br />
                <span style={{ fontSize: 11, color: '#94a3b8' }}>Top 3 drifting features tracked</span>
              </div>
            </div>
            {/* Tier 3 */}
            <div style={{ background: '#f8fafc', borderRadius: 10, padding: 16, border: '1px solid #e2e8f0' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8 }}>
                Tier 3 — Policy Engine
              </div>
              <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.7 }}>
                <strong>Rule-based</strong> (5 policy checks)<br />
                COMPLIANT (0 violations): <strong>0 pts</strong><br />
                SOFT_DRIFT (1 violation): <strong>&minus;15 pts</strong><br />
                HARD_VIOLATION (2+): <strong>&minus;40 pts</strong><br />
                <span style={{ fontSize: 11, color: '#94a3b8' }}>Protocol &bull; Port &bull; Destination &bull; Volume &bull; Direction</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: 14, padding: '10px 14px', borderRadius: 8, background: '#eff6ff', border: '1px solid #bfdbfe', fontSize: 12, color: '#1e40af' }}>
            <strong>Formula:</strong> Trust = max(0, min(100, 100 &minus; anomaly_deduction &minus; drift_deduction &minus; policy_deduction))
            &nbsp;&nbsp;|&nbsp;&nbsp;Higher-impact violations carry larger deductions to prioritize explicit misuse over statistical noise.
          </div>
        </div>
      </div>
    </div>
  );
}


/* ─── Device Fingerprint Card ─── */
function ProfileCard({ profile }) {
  return (
    <div style={{
      background: '#fff', borderRadius: 12, padding: 20,
      border: '1px solid #e2e8f0', boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 15, fontWeight: 600, color: '#1a1a2e' }}>{profile.device_type}</div>
          <div style={{ fontSize: 12, color: '#64748b' }}>{profile.description}</div>
        </div>
        <div style={{
          padding: '4px 10px', borderRadius: 6, background: '#eff6ff',
          color: '#2563eb', fontSize: 11, fontWeight: 600,
        }}>FINGERPRINT</div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12 }}>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Protocols</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{profile.allowed_protocols.join(', ')}</span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Ports</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{profile.allowed_ports.join(', ')}</span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Dest IPs</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500, fontFamily: 'monospace', fontSize: 11 }}>{profile.allowed_dst_ips.join(', ')}</span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>External Traffic</span>
          <span style={{ color: profile.allow_external ? '#f59e0b' : '#22c55e', fontWeight: 600 }}>
            {profile.allow_external ? 'Allowed' : 'Blocked'}
          </span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Bytes / Flow</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>
            {formatBytes(profile.bytes_range_min)} &ndash; {formatBytes(profile.bytes_range_max)}
          </span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>BW Max / hr</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{formatBytes(profile.bandwidth_max_bytes)}</span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Max Dest IPs</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{profile.max_unique_dst_ips}</span>
        </div>
        <div style={{ padding: '8px 10px', borderRadius: 6, background: '#f8fafc' }}>
          <span style={{ color: '#94a3b8', display: 'block', fontSize: 10, textTransform: 'uppercase', fontWeight: 600, marginBottom: 2 }}>Direction</span>
          <span style={{ color: '#1a1a2e', fontWeight: 500 }}>{profile.expected_directions.join(', ')}</span>
        </div>
      </div>
    </div>
  );
}


/* ─── Live Assessment Panel ─── */
function AssessmentPanel({ devices }) {
  const [selectedDevice, setSelectedDevice] = useState('');
  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(false);

  const runAssessment = async () => {
    if (!selectedDevice) return;
    setLoading(true);
    try {
      const res = await axios.get(`${API}/device/${selectedDevice}/assessment`);
      setAssessment(res.data);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  const sev = assessment ? severityClass(assessment.severity) : '';

  return (
    <div className="panel" style={{ marginBottom: 24 }}>
      <div className="panel-header">
        <div>
          <div className="panel-title">Live Trust Assessment</div>
          <div className="panel-subtitle">Select a device to see the full 3-tier trust breakdown</div>
        </div>
      </div>
      <div className="panel-body">
        {/* Device Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
          <select
            value={selectedDevice}
            onChange={e => { setSelectedDevice(e.target.value); setAssessment(null); }}
            style={{
              padding: '10px 14px', borderRadius: 8, border: '1px solid #e2e8f0',
              fontSize: 14, fontFamily: 'inherit', background: '#f8fafc',
              color: '#1a1a2e', minWidth: 280, cursor: 'pointer',
            }}
          >
            <option value="">-- Select Device --</option>
            {devices.map(d => (
              <option key={d.device_id} value={d.device_id}>
                {d.device_id} ({d.device_type}, Trust: {d.trust_score})
              </option>
            ))}
          </select>
          <button
            onClick={runAssessment}
            disabled={!selectedDevice || loading}
            style={{
              padding: '10px 24px', borderRadius: 8, border: 'none',
              background: selectedDevice ? '#3b82f6' : '#94a3b8',
              color: 'white', fontWeight: 600, fontSize: 14, fontFamily: 'inherit',
              cursor: selectedDevice ? 'pointer' : 'not-allowed',
              transition: 'background 0.2s',
            }}
          >
            {loading ? 'Analyzing...' : 'Run Assessment'}
          </button>
        </div>

        {/* Results */}
        {assessment && assessment.found && (
          <>
            {/* 4 Cards: Ensemble + 3 Tiers */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 20 }}>
              {/* Ensemble Score */}
              <div style={{
                background: '#fff', borderRadius: 12, padding: 20,
                border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6 }}>
                  Ensemble Trust Score
                </div>
                <div style={{ fontSize: 42, fontWeight: 700, letterSpacing: -2, color: sev === 'low' ? '#22c55e' : sev === 'medium' ? '#f59e0b' : sev === 'high' ? '#ef4444' : '#991b1b' }}>
                  {assessment.trust_score_smoothed}
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>Out of 100.0</div>
                <div style={{ marginTop: 8 }}>
                  <span className={`severity-badge ${sev}`}>{assessment.severity}</span>
                </div>
              </div>

              {/* Tier 1: ML Anomaly */}
              <div style={{
                background: '#fff', borderRadius: 12, padding: 20,
                border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: '#3b82f6', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
                  Tier 1 (ML Anomaly)
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 6 }}>
                  Score: <span style={{ fontSize: 22, fontWeight: 700 }}>{assessment.anomaly_score}</span>
                </div>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Deduction: <strong style={{ color: assessment.anomaly_deduction > 0 ? '#ef4444' : '#22c55e' }}>
                    {assessment.anomaly_deduction > 0 ? `-${assessment.anomaly_deduction}` : '0'} pts
                  </strong>
                </div>
                <div style={{
                  marginTop: 8, height: 4, background: '#f0f2f5', borderRadius: 2, overflow: 'hidden',
                }}>
                  <div style={{
                    height: '100%', borderRadius: 2,
                    width: `${Math.min(assessment.anomaly_score * 100, 100)}%`,
                    background: assessment.anomaly_score > 0.5 ? '#ef4444' : assessment.anomaly_score > 0.25 ? '#f59e0b' : '#22c55e',
                  }} />
                </div>
                <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 6 }}>Isolation Forest</div>
              </div>

              {/* Tier 2: Stat Drift */}
              <div style={{
                background: '#fff', borderRadius: 12, padding: 20,
                border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: '#f59e0b', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
                  Tier 2 (Stat Drift)
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 6 }}>
                  Class: <span style={{
                    fontSize: 14, fontWeight: 700,
                    color: assessment.drift.drift_class === 'DRIFT_STRONG' ? '#ef4444' :
                           assessment.drift.drift_class === 'DRIFT_MILD' ? '#f59e0b' : '#22c55e',
                  }}>
                    {assessment.drift.drift_class.replace('DRIFT_', '')}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Deduction: <strong style={{ color: assessment.drift.penalty > 0 ? '#ef4444' : '#22c55e' }}>
                    {assessment.drift.penalty > 0 ? `-${assessment.drift.penalty}` : '0'} pts
                  </strong>
                </div>
                <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
                  Z-magnitude: <strong>{assessment.drift.drift_magnitude}</strong>
                </div>
                <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 6 }}>Z-Score Analysis</div>
              </div>

              {/* Tier 3: Policy */}
              <div style={{
                background: '#fff', borderRadius: 12, padding: 20,
                border: '1px solid #e2e8f0', boxShadow: '0 2px 8px rgba(0,0,0,0.04)',
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: '#ef4444', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 4 }}>
                  Tier 3 (Policy Engine)
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 6 }}>
                  Status: <span style={{
                    fontSize: 14, fontWeight: 700,
                    color: assessment.policy.policy_status === 'HARD_VIOLATION' ? '#ef4444' :
                           assessment.policy.policy_status === 'SOFT_DRIFT' ? '#f59e0b' : '#22c55e',
                  }}>
                    {assessment.policy.policy_status.replace('_', ' ')}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: '#64748b' }}>
                  Deduction: <strong style={{ color: assessment.policy.penalty > 0 ? '#ef4444' : '#22c55e' }}>
                    {assessment.policy.penalty > 0 ? `-${assessment.policy.penalty}` : '0'} pts
                  </strong>
                </div>
                <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
                  {assessment.policy.violations !== 'none' ? assessment.policy.violations : 'No violations'}
                </div>
                <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 6 }}>Rule-Based (5 Checks)</div>
              </div>
            </div>

            {/* Score Waterfall */}
            <div style={{
              background: '#f8fafc', borderRadius: 10, padding: 16,
              border: '1px solid #e2e8f0', marginBottom: 16,
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 10 }}>Score Waterfall</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', fontSize: 13 }}>
                <span style={{ fontWeight: 600, color: '#22c55e', background: '#f0fdf4', padding: '4px 10px', borderRadius: 6 }}>
                  100
                </span>
                <span style={{ color: '#94a3b8' }}>&rarr;</span>
                {assessment.anomaly_deduction > 0 && (
                  <>
                    <span style={{ fontWeight: 600, color: '#ef4444', background: '#fef2f2', padding: '4px 10px', borderRadius: 6 }}>
                      &minus;{assessment.anomaly_deduction.toFixed(1)} Anomaly
                    </span>
                    <span style={{ color: '#94a3b8' }}>&rarr;</span>
                  </>
                )}
                {assessment.drift.penalty > 0 && (
                  <>
                    <span style={{ fontWeight: 600, color: '#f59e0b', background: '#fffbeb', padding: '4px 10px', borderRadius: 6 }}>
                      &minus;{assessment.drift.penalty} Drift ({assessment.drift.drift_class.replace('DRIFT_', '')})
                    </span>
                    <span style={{ color: '#94a3b8' }}>&rarr;</span>
                  </>
                )}
                {assessment.policy.penalty > 0 && (
                  <>
                    <span style={{ fontWeight: 600, color: '#ef4444', background: '#fef2f2', padding: '4px 10px', borderRadius: 6 }}>
                      &minus;{assessment.policy.penalty} Policy ({assessment.policy.policy_status.replace('_', ' ')})
                    </span>
                    <span style={{ color: '#94a3b8' }}>&rarr;</span>
                  </>
                )}
                <span style={{
                  fontWeight: 700, fontSize: 15,
                  padding: '4px 12px', borderRadius: 6,
                  color: sev === 'low' ? '#15803d' : sev === 'medium' ? '#b45309' : '#dc2626',
                  background: sev === 'low' ? '#f0fdf4' : sev === 'medium' ? '#fffbeb' : '#fef2f2',
                }}>
                  = {assessment.trust_score_raw} (raw) &rarr; {assessment.trust_score_smoothed} (smoothed)
                </span>
              </div>
            </div>

            {/* Evidence */}
            {assessment.evidence && assessment.evidence.risk_summary && (
              <div style={{
                background: '#fff', borderRadius: 10, padding: 16,
                border: '1px solid #e2e8f0',
              }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#1a1a2e', marginBottom: 8 }}>
                  XAI Evidence (Auto-Generated)
                </div>
                <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.7 }}>
                  <strong>Risk Summary:</strong> {assessment.evidence.risk_summary}<br />
                  <strong>Evidence:</strong> {assessment.evidence.evidence}<br />
                  <strong>Attribution:</strong> {assessment.evidence.feature_attribution}<br />
                  <strong>Recommended Action:</strong> {assessment.evidence.recommended_action}
                </div>
              </div>
            )}
          </>
        )}

        {assessment && !assessment.found && (
          <div className="table-empty">Device not found in pipeline data.</div>
        )}

        {!assessment && !loading && (
          <div style={{ textAlign: 'center', padding: 24, color: '#94a3b8', fontSize: 13 }}>
            Select a device and click "Run Assessment" to see the full trust breakdown.
          </div>
        )}
      </div>
    </div>
  );
}


/* ─── Main Page ─── */
function Devices() {
  const [profiles, setProfiles] = useState([]);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchData() {
      try {
        const [pRes, dRes] = await Promise.all([
          axios.get(`${API}/device-profiles`),
          axios.get(`${API}/devices`),
        ]);
        setProfiles(pRes.data);
        setDevices(dRes.data);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) {
    return <div className="loading-container"><div className="loading-spinner" /><div className="loading-text">Loading device data...</div></div>;
  }

  return (
    <>
      <div className="page-title-section">
        <h1 className="page-title">Devices & Trust Scoring</h1>
        <p className="page-subtitle">Device fingerprinting, behavioral profiling, and transparent trust methodology</p>
      </div>

      {/* Trust Methodology */}
      <TrustMethodology />

      {/* Live Assessment */}
      <AssessmentPanel devices={devices} />

      {/* Device Profiles / Fingerprints */}
      <div className="panel" style={{ marginBottom: 24 }}>
        <div className="panel-header">
          <div>
            <div className="panel-title">Device Behavioral Fingerprints</div>
            <div className="panel-subtitle">Baseline profiles defining "what is normal" for each device type</div>
          </div>
        </div>
        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 16 }}>
            {profiles.map(p => <ProfileCard key={p.device_type} profile={p} />)}
          </div>
        </div>
      </div>
    </>
  );
}

export default Devices;

