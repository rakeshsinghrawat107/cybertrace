// CyberTrace Investigation Portal Frontend Logic

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const progressBar = document.getElementById('progress-bar');
  const progressFill = document.getElementById('progress-fill');
  const resultsGrid = document.getElementById('results-grid');

  // Quick Demo Buttons
  document.getElementById('btn-demo-clean').addEventListener('click', () => triggerDemo('clean'));
  document.getElementById('btn-demo-phish').addEventListener('click', () => triggerDemo('phishing'));
  document.getElementById('btn-demo-quish').addEventListener('click', () => triggerDemo('quishing'));

  // Drag & drop handlers
  dropzone.addEventListener('click', () => fileInput.click());
  
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      uploadFile(e.target.files[0]);
    }
  });

  // Verify button handler
  document.getElementById('btn-verify-integrity').addEventListener('click', () => {
    const caseId = currentCaseId;
    if (!caseId) return;
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.eml';
    input.onchange = async (e) => {
      if (e.target.files.length > 0) {
        verifyFileIntegrity(caseId, e.target.files[0]);
      }
    };
    input.click();
  });
});

let currentCaseId = null;

async function triggerDemo(sampleType) {
  showProgress();
  try {
    const res = await fetch(`/cases/demo/${sampleType}`, { method: 'POST' });
    if (!res.ok) throw new Error(`Demo failed: ${res.statusText}`);
    const data = await res.json();
    renderAnalysis(data);
  } catch (err) {
    alert(`Error running demo: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function uploadFile(file) {
  showProgress();
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/cases', {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`);
    const data = await res.json();
    renderAnalysis(data);
  } catch (err) {
    alert(`Error analyzing file: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function verifyFileIntegrity(caseId, file) {
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(`/cases/${caseId}/verify`, {
      method: 'POST',
      body: formData,
    });
    const result = await res.json();
    if (result.match) {
      alert(`[MATHEMATICALLY PROVED: ZERO HASH DRIFT]\n\nCase ID: ${caseId}\nStatus: CRYPTOGRAPHIC MATCH\nAdmissibility: VALID SECTION 63 BSA 2023\nDigest: ${result.original_hash}`);
    } else {
      alert(`[CRITICAL SECURITY ALERT: HASH DRIFT DETECTED]\n\nCase ID: ${caseId}\nStatus: TAMPERED / ALTERED EVIDENCE\nOriginal: ${result.original_hash}\nRe-upload: ${result.uploaded_hash}`);
    }
  } catch (err) {
    alert(`Verification error: ${err.message}`);
  }
}

function showProgress() {
  const pBar = document.getElementById('progress-bar');
  const pFill = document.getElementById('progress-fill');
  pBar.style.display = 'block';
  pFill.style.width = '20%';
  setTimeout(() => { pFill.style.width = '70%'; }, 200);
}

function hideProgress() {
  const pBar = document.getElementById('progress-bar');
  const pFill = document.getElementById('progress-fill');
  pFill.style.width = '100%';
  setTimeout(() => {
    pBar.style.display = 'none';
    pFill.style.width = '0%';
  }, 400);
}

function renderAnalysis(data) {
  currentCaseId = data.case_id;
  const grid = document.getElementById('results-grid');
  grid.style.display = 'grid';

  // 1. Threat Gauge
  const score = data.risk.score;
  const band = data.risk.band;
  document.getElementById('risk-score-text').innerText = score.toFixed(2);
  const badge = document.getElementById('threat-band-badge');
  badge.innerText = band;
  badge.className = `threat-band-badge band-${band}`;

  // SVG circle arc offset: radius 58 -> circumference = 2 * PI * 58 = 364.42
  const circ = 364.42;
  const offset = circ - (score * circ);
  const circleBar = document.getElementById('gauge-bar');
  circleBar.style.strokeDasharray = circ;
  circleBar.style.strokeDashoffset = offset;
  
  if (band === 'LOW') circleBar.style.stroke = 'var(--risk-low)';
  else if (band === 'MEDIUM') circleBar.style.stroke = 'var(--risk-medium)';
  else if (band === 'HIGH') circleBar.style.stroke = 'var(--risk-high)';
  else circleBar.style.stroke = 'var(--risk-critical)';

  document.getElementById('risk-rationale').innerText = data.risk.rationale;

  // 2. Component breakdown bars
  const compContainer = document.getElementById('component-bars');
  compContainer.innerHTML = '';
  const scores = data.risk.component_scores || {};
  const weights = data.risk.component_weights || {};

  for (const [key, val] of Object.entries(scores)) {
    const weight = weights[key] || 0.1;
    const pct = Math.round(val * 100);
    const label = key.replace(/_/g, ' ').toUpperCase();
    
    const row = document.createElement('div');
    row.className = 'comp-bar-row';
    row.innerHTML = `
      <div class="comp-bar-labels">
        <span>${label} (Weight: ${weight})</span>
        <span class="mono">${val.toFixed(2)}</span>
      </div>
      <div class="comp-bar-track">
        <div class="comp-bar-fill" style="width: ${pct}%; background: ${getCompColor(val)}"></div>
      </div>
    `;
    compContainer.appendChild(row);
  }

  // 3. Case Metadata & Digest
  document.getElementById('meta-case-id').innerText = data.case_id;
  document.getElementById('meta-timestamp').innerText = data.ingested_at.substring(0, 19).replace('T', ' ') + ' UTC';
  document.getElementById('meta-filename').innerText = data.evidence.original_filename;
  document.getElementById('meta-sha256').innerText = data.evidence.sha256;
  document.getElementById('meta-size').innerText = `${data.evidence.size_bytes} bytes`;

  // Auth Badges
  const auth = data.email.headers._auth_verdicts || {};
  document.getElementById('auth-spf').innerText = (auth.spf || 'NONE').toUpperCase();
  document.getElementById('auth-dkim').innerText = (auth.dkim || 'NONE').toUpperCase();
  document.getElementById('auth-dmarc').innerText = (auth.dmarc || 'NONE').toUpperCase();

  // 4. Received Hop Pathway
  const hopContainer = document.getElementById('hop-timeline');
  hopContainer.innerHTML = '';
  const hops = data.email.headers._parsed_received_hops || [];
  if (hops.length === 0) {
    hopContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No external RFC Received hops parsed.</p>';
  } else {
    hops.forEach(h => {
      const hopEl = document.createElement('div');
      hopEl.className = 'hop-item';
      hopEl.innerHTML = `
        <div class="hop-badge">${h.hop}</div>
        <div class="hop-content">
          <div class="hop-main">${h.ip || 'Private Subnet'} (${h.is_private ? 'Internal Hop' : 'Public Egress Data Center'})</div>
          <div class="hop-details">From: <code>${h.from_host || 'N/A'}</code> | By: <code>${h.by_host || 'N/A'}</code></div>
        </div>
      `;
      hopContainer.appendChild(hopEl);
    });
  }

  // 5. De-obfuscation & Cloaking Surfaced
  const obfContainer = document.getElementById('obfuscation-list');
  obfContainer.innerHTML = '';
  const hiddenLogs = data.email.hidden_content_removed || [];
  if (hiddenLogs.length === 0) {
    obfContainer.innerHTML = '<p style="color: #34d399; font-size: 12px;">✅ No zero-width characters or CSS cloaked elements detected.</p>';
  } else {
    hiddenLogs.forEach(log => {
      const b = document.createElement('div');
      b.className = 'obf-badge';
      b.innerText = log;
      obfContainer.appendChild(b);
    });
  }

  // 6. QR Quishing Forensics
  const qrContainer = document.getElementById('qr-details');
  const qrPayloads = data.indicators.qr_payloads || [];
  if (qrPayloads.length === 0) {
    qrContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No image QR codes detected in attachments or inline MIME parts.</p>';
  } else {
    qrContainer.innerHTML = `
      <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 12px;">
        <div style="color: #f87171; font-weight: 700; font-size: 13px; margin-bottom: 6px;">⚠️ MULTIMODAL QR QUISHING PAYLOAD DETECTED</div>
        <div class="mono" style="font-size: 12px; word-break: break-all; color: #fff;">${qrPayloads[0]}</div>
      </div>
    `;
  }

  // 7. Incident Story (Zero-Hallucination)
  const storyContainer = document.getElementById('story-steps');
  storyContainer.innerHTML = '';
  const storySteps = data.attack_story || [];
  if (storySteps.length === 0) {
    storyContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">Standard transactional message. No threat indicators surfaced.</p>';
  } else {
    storySteps.forEach(s => {
      const stepEl = document.createElement('div');
      stepEl.className = 'story-step';
      const citations = s.cited_findings.map(c => `<span class="citation-tag">${c}</span>`).join(' ');
      stepEl.innerHTML = `<b>[Step ${s.step_number}]</b> ${s.statement} ${citations}`;
      storyContainer.appendChild(stepEl);
    });
  }

  // 8. Attack DNA Vector & Top Match
  const campContainer = document.getElementById('campaign-matches');
  campContainer.innerHTML = '';
  const matches = data.attack_dna.top_matches || [];
  if (matches.length === 0) {
    campContainer.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No congruent campaign cluster matches found (cosine similarity < 0.70).</p>';
  } else {
    matches.forEach(m => {
      const mEl = document.createElement('div');
      mEl.style = 'background: rgba(99, 102, 241, 0.1); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 8px; padding: 12px; margin-bottom: 8px;';
      mEl.innerHTML = `
        <div style="display: flex; justify-content: space-between; font-weight: 700; font-size: 13px; color: #a5b4fc;">
          <span>${m.case_id}</span>
          <span>${(m.similarity_score * 100).toFixed(1)}% Match</span>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">Drivers: ${m.drivers.join(', ')}</div>
      `;
      campContainer.appendChild(mEl);
    });
  }

  // 9. Download Links
  document.getElementById('link-pdf').href = `/cases/${data.case_id}/report.pdf`;
  document.getElementById('link-zip').href = `/cases/${data.case_id}/evidence.zip`;

  // Scroll to results smoothly
  grid.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function getCompColor(val) {
  if (val >= 0.7) return 'var(--risk-critical)';
  if (val >= 0.4) return 'var(--risk-high)';
  if (val >= 0.2) return 'var(--risk-medium)';
  return 'var(--risk-low)';
}
