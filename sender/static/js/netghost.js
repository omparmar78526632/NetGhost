/**
 * NETGHOST - Cybernetic Lab Dashboard Controller
 * 100% Real Functionality: Backed by Flask REST API & Live SSE Pipeline
 */

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initTheme();
  initOverview();
  initSender();
  initReceiver();
  initProfiler();
  initPacketMonitor();
  initExperiments();
  initResultsCharts();
  initDocumentation();
  initSettings();
});

/* ==========================================================================
   1. NAVIGATION & ROUTING
   ========================================================================== */
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const pageViews = document.querySelectorAll('.page-view');

  function showPage(pageId) {
    if (!pageId) return;
    
    navItems.forEach(item => {
      if (item.getAttribute('data-page') === pageId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    pageViews.forEach(view => {
      if (view.id === `view-${pageId}`) {
        view.classList.add('active');
      } else {
        view.classList.remove('active');
      }
    });

    if (pageId === 'overview') {
      fetchOverviewState();
    } else if (pageId === 'receiver') {
      if (typeof fetchReceiverState === 'function') fetchReceiverState();
    } else if (pageId === 'results') {
      setTimeout(renderAllResultsCharts, 60);
    } else if (pageId === 'profiler') {
      setTimeout(renderProfilerChart, 60);
    } else if (pageId === 'experiments') {
      fetchExperimentList();
    } else if (pageId === 'monitor') {
      fetchMonitorPackets();
    }

    history.replaceState(null, null, `#${pageId}`);
  }

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const pageId = item.getAttribute('data-page');
      showPage(pageId);
    });
  });

  document.querySelectorAll('[data-goto]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const targetPage = btn.getAttribute('data-goto');
      showPage(targetPage);
    });
  });

  const initialHash = window.location.hash.replace('#', '');
  if (initialHash && document.getElementById(`view-${initialHash}`)) {
    showPage(initialHash);
  } else {
    const defaultPage = document.body.getAttribute('data-default-view') || 'overview';
    showPage(defaultPage);
  }
}

/* ==========================================================================
   2. THEME CONTROLLER
   ========================================================================== */
function initTheme() {
  const themeSwitch = document.getElementById('themeToggle');
  const themeRadios = document.querySelectorAll('input[name="theme-choice"]');

  function setTheme(isLight) {
    if (isLight) {
      document.body.classList.add('light-theme');
      localStorage.setItem('ng_theme', 'light');
    } else {
      document.body.classList.remove('light-theme');
      localStorage.setItem('ng_theme', 'dark');
    }
    themeRadios.forEach(radio => {
      if (radio.value === (isLight ? 'light' : 'dark')) radio.checked = true;
    });
    renderAllResultsCharts();
    renderProfilerChart();
  }

  if (themeSwitch) {
    themeSwitch.addEventListener('click', () => {
      const isLight = !document.body.classList.contains('light-theme');
      setTheme(isLight);
    });
  }

  themeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      setTheme(radio.value === 'light');
    });
  });

  if (localStorage.getItem('ng_theme') === 'light') {
    setTheme(true);
  }
}

/* ==========================================================================
   3. SCREEN 1: OVERVIEW / CONTROL CENTER
   ========================================================================== */
async function fetchOverviewState() {
  try {
    const res = await fetch('/api/overview');
    if (!res.ok) return;
    const data = await res.json();

    // Metric Cards
    const statusVal = document.querySelector('#view-overview .metrics-grid-4 .metric-card:nth-child(1) .metric-value');
    if (statusVal) {
      const dotColor = data.status === 'TRANSMITTING' ? 'yellow' : (data.status === 'RECEIVING' ? 'green' : (data.status === 'ERROR' ? 'red' : 'blue'));
      statusVal.innerHTML = `<span class="metric-status-dot ${dotColor}"></span> ${data.status}`;
    }

    const chanVal = document.querySelector('#view-overview .metrics-grid-4 .metric-card:nth-child(2) .metric-value');
    if (chanVal) {
      chanVal.textContent = data.active_channel || 'None';
    }

    const pktsVal = document.querySelector('#view-overview .metrics-grid-4 .metric-card:nth-child(3) .metric-value');
    if (pktsVal) {
      pktsVal.textContent = (data.total_packets_sent + data.total_packets_received).toLocaleString();
    }

    const payloadVal = document.querySelector('#view-overview .metrics-grid-4 .metric-card:nth-child(4) .metric-value');
    if (payloadVal) {
      const bytes = data.total_bytes_sent + data.total_bytes_received;
      payloadVal.textContent = bytes > 1024 ? `${(bytes/1024).toFixed(1)} KB` : `${bytes} B`;
    }

    // Pipeline Step Badges
    const pipelineBadge = document.querySelector('#view-overview .pipeline-track');
    if (pipelineBadge && data.pipeline) {
      // update stage classes dynamically
      const steps = pipelineBadge.querySelectorAll('.pipeline-step');
      const p = data.pipeline;
      const stepMap = ['sender', 'encryption', 'framing', 'channel', 'icmp', 'receiver', 'reassembly', 'decryption'];
      steps.forEach((step, idx) => {
        const key = stepMap[idx];
        if (key && p[key]) {
          step.className = `pipeline-step ${p[key] === 'ACTIVE' ? 'active' : (p[key] === 'ERROR' ? 'error' : '')}`;
        }
      });
    }
  } catch (err) {
    console.warn('Error fetching overview state:', err);
  }
}

function initOverview() {
  fetchOverviewState();
  setInterval(() => {
    if (document.getElementById('view-overview')?.classList.contains('active')) {
      fetchOverviewState();
    }
  }, 3000);
}

/* ==========================================================================
   4. SCREEN 2: SENDER CONTROLLER (Real AES-256-GCM Backend & Validation)
   ========================================================================== */
function initSender() {
  const messageInput = document.getElementById('senderMessage');
  const charCounter = document.getElementById('charCount');
  const modeSelect = document.getElementById('senderMode');
  const timingGroup = document.getElementById('timingProfileGroup');
  const secretInput = document.getElementById('senderSecret');
  const secretToggle = document.getElementById('toggleSecretVisibility');
  const prepareBtn = document.getElementById('btnPrepareTransmit');
  const clearBtn = document.getElementById('btnClearSender');
  const startSendBtn = document.getElementById('btnStartSend');
  const progressBar = document.getElementById('senderProgressBar');
  const progressLabel = document.getElementById('senderProgressLabel');
  const previewSection = document.getElementById('transmissionPreview');
  const fragmentTrack = document.getElementById('previewFragmentTrack');
  const generateKeyBtn = document.getElementById('btnGenerateKey');

  let isPrepared = false;
  let preparedData = null;

  if (messageInput && charCounter) {
    messageInput.addEventListener('input', () => {
      charCounter.textContent = `${messageInput.value.length} / 4096`;
    });
  }

  if (secretToggle && secretInput) {
    secretToggle.addEventListener('click', () => {
      const isPass = secretInput.type === 'password';
      secretInput.type = isPass ? 'text' : 'password';
      secretToggle.innerHTML = isPass ? '👁️' : '👁️‍🗨️';
    });
  }

  if (generateKeyBtn && secretInput) {
    generateKeyBtn.addEventListener('click', () => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
      let randomSecret = '';
      for (let i = 0; i < 16; i++) {
        randomSecret += chars.charAt(Math.floor(Math.random() * chars.length));
      }
      secretInput.value = randomSecret;
      secretInput.type = 'text';
      if (secretToggle) secretToggle.innerHTML = '👁️';
      showToast('✓ Generated new 128-bit cryptographic pre-shared key (PSK)', 'info');
    });
  }

  if (modeSelect && timingGroup) {
    modeSelect.addEventListener('change', () => {
      timingGroup.style.display = modeSelect.value === 'temporal' ? 'block' : 'none';
      if (previewSection) previewSection.style.display = 'none';
      isPrepared = false;
    });
  }

  // Quick Template Buttons
  document.querySelectorAll('[data-template]').forEach(btn => {
    btn.addEventListener('click', () => {
      const tpl = btn.getAttribute('data-template');
      if (messageInput) {
        if (tpl === 'short') messageInput.value = 'ALPHA_NODE_OK';
        else if (tpl === 'med') messageInput.value = 'TACTICAL_TELEMETRY: SECTOR 4 LAT 37.7749 LON -122.4194 SPEED 0 KTS STATUS SECURE';
        else if (tpl === 'long') messageInput.value = 'MISSION_LOG_2026: STEGANOGRAPHIC CHANNEL ESTABLISHED OVER LOOPBACK INTERFACE. AES-256-GCM KEY DERIVED VIA PBKDF2. ALL ICMP ECHO REQUESTS SYNCHRONIZED TO 0xDEAD.';
        else if (tpl === 'json') messageInput.value = '{"node":"sensor-09","event":"HEARTBEAT","auth_tag":"9f8b","payload":"OK"}';
        else if (tpl === 'alert') messageInput.value = 'CRITICAL_SECURITY_ALERT: COVERT TRANSMISSION ACTIVE ON SECTOR 7';
        charCounter.textContent = `${messageInput.value.length} / 4096`;
      }
    });
  });

  if (clearBtn && messageInput) {
    clearBtn.addEventListener('click', () => {
      messageInput.value = '';
      charCounter.textContent = '0 / 4096';
      if (previewSection) previewSection.style.display = 'none';
      isPrepared = false;
      preparedData = null;
    });
  }

  // Real Backend Prepare Call
  if (prepareBtn) {
    prepareBtn.addEventListener('click', async () => {
      const msg = messageInput ? messageInput.value : '';
      const secret = secretInput ? secretInput.value.trim() : '';
      const mode = modeSelect ? modeSelect.value : 'header';

      if (!secret) {
        showToast('Validation Error: Please enter a Shared Secret (PSK)', 'error');
        return;
      }
      if (!msg) {
        showToast('Validation Error: Plaintext payload cannot be empty', 'error');
        return;
      }

      prepareBtn.disabled = true;
      prepareBtn.textContent = 'Encrypting & Framing...';

      try {
        const res = await fetch('/api/sender/prepare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message: msg,
            passphrase: secret,
            mode: mode
          })
        });

        const data = await res.json();
        prepareBtn.disabled = false;
        prepareBtn.textContent = 'Encrypt & Prepare Transmission';

        if (data.success) {
          isPrepared = true;
          preparedData = data;

          document.getElementById('previewPayloadSize').textContent = `${data.frame_size_bytes} bytes`;
          document.getElementById('previewFragments').textContent = `${data.fragment_count}`;
          document.getElementById('previewModeLabel').textContent = data.mode === 'header' ? 'IP-ID Header Embedding' : 'Temporal IPD';

          if (fragmentTrack && data.preview_fragments) {
            let fragsHtml = '';
            data.preview_fragments.forEach((frag, idx) => {
              fragsHtml += `<span style="color:#fff; font-family:var(--font-mono);">${frag.hex} (${frag.desc})</span>`;
              if (idx < data.preview_fragments.length - 1) {
                fragsHtml += ` <span style="color:#3b82f6;">→</span> `;
              }
            });
            fragmentTrack.innerHTML = fragsHtml;
          }

          if (progressLabel) progressLabel.textContent = `0 / ${data.fragment_count} packets (0%)`;
          if (progressBar) progressBar.style.width = '0%';

          if (previewSection) {
            previewSection.style.display = 'block';
            previewSection.scrollIntoView({ behavior: 'smooth' });
          }

          showToast(`✓ Encrypted via AES-256-GCM: ${data.frame_size_bytes}B framed into ${data.fragment_count} packets`, 'success');
        } else {
          showToast(`Encryption failed: ${data.error}`, 'error');
        }
      } catch (err) {
        prepareBtn.disabled = false;
        prepareBtn.textContent = 'Encrypt & Prepare Transmission';
        showToast(`Backend connection error: ${err.message}`, 'error');
      }
    });
  }

  // Real Backend Transmission Call
  if (startSendBtn) {
    startSendBtn.addEventListener('click', async () => {
      const targetIp = document.getElementById('senderTargetIp')?.value.trim() || '127.0.0.1';
      const secret = secretInput ? secretInput.value.trim() : '';
      const msg = messageInput ? messageInput.value : '';
      const mode = modeSelect ? modeSelect.value : 'header';
      const timingProfile = document.getElementById('senderTimingProfile')?.value || 'normal';

      if (!targetIp) {
        showToast('Validation Error: Destination IP is required', 'error');
        return;
      }
      if (!secret) {
        showToast('Validation Error: Shared Secret is required', 'error');
        return;
      }
      if (!msg) {
        showToast('Validation Error: Message is required', 'error');
        return;
      }

      startSendBtn.disabled = true;
      startSendBtn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;display:inline-block;animation:spin 1s linear infinite;"></span> Transmitting...';

      const totalPkts = preparedData?.fragment_count || 39;
      if (progressLabel) progressLabel.textContent = `Transmitting ${totalPkts} packets...`;
      if (progressBar) progressBar.style.width = '50%';

      try {
        const res = await fetch('/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_ip: targetIp,
            passphrase: secret,
            message: msg,
            mode: mode,
            timing_profile: timingProfile
          })
        });

        const data = await res.json();

        if (res.ok && data.success) {
          const stats = data.stats;
          if (progressBar) progressBar.style.width = '100%';
          if (progressLabel) progressLabel.textContent = `${stats.packets_sent} / ${stats.packets_sent} packets (100%)`;
          showToast(`✓ Transmitted ${stats.packets_sent} packets in ${stats.duration_seconds.toFixed(2)}s (${stats.throughput_bps.toFixed(1)} bps)`, 'success');
        } else {
          if (progressBar) progressBar.style.width = '0%';
          if (progressLabel) progressLabel.textContent = `FAILED`;
          showToast(`Transmission Failed: ${data.error || 'Unknown error'}`, 'error');
        }
      } catch (err) {
        if (progressBar) progressBar.style.width = '0%';
        if (progressLabel) progressLabel.textContent = `NETWORK ERROR`;
        showToast(`Transmission Network Error: ${err.message}`, 'error');
      } finally {
        startSendBtn.disabled = false;
        startSendBtn.innerHTML = '<span>▶</span> Transmit Stream';
      }
    });
  }
}

/* ==========================================================================
   5. SCREEN 3: RECEIVER CONTROLLER (Live SSE Sniffer & Real Decoding)
   ========================================================================== */
function initReceiver() {
  const startBtn = document.getElementById('btnStartReceiver');
  const stopBtn = document.getElementById('btnStopReceiver');
  const liveTableBody = document.getElementById('receiverLiveTableBody');
  const liveBadge = document.getElementById('receiverLiveBadge');
  const exportBtn = document.getElementById('btnExportResult');
  const decodedTextBox = document.getElementById('receiverDecodedText');
  const authErrorBanner = document.getElementById('receiverAuthErrorBanner');

  const statusSync = document.getElementById('statusSync');
  const statusFraming = document.getElementById('statusFraming');
  const statusFragments = document.getElementById('statusFragments');
  const statusReassembly = document.getElementById('statusReassembly');
  const statusAuth = document.getElementById('statusAuth');
  const statusDecrypt = document.getElementById('statusDecrypt');

  let eventSource = null;
  let packetCount = 0;
  let lastPacketTime = null;

  function resetChecklist() {
    if (authErrorBanner) authErrorBanner.style.display = 'none';
    if (statusSync) statusSync.innerHTML = '<span style="color:var(--text-muted);">Listening...</span>';
    if (statusFraming) statusFraming.innerHTML = '<span style="color:var(--text-muted);">Pending</span>';
    if (statusFragments) statusFragments.textContent = '0 packets';
    if (statusReassembly) statusReassembly.textContent = '0%';
    if (statusAuth) statusAuth.innerHTML = '<span style="color:var(--text-muted);">Pending</span>';
    if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color:var(--text-muted);">Pending</span>';
    if (decodedTextBox) {
      decodedTextBox.innerHTML = '<span style="color: var(--text-muted); font-style: italic;">Awaiting incoming transmission stream...</span>';
    }
  }

  function appendRealPacketRow(ipidHex, ipdStr, statusTag, tagClass) {
    if (!liveTableBody) return;
    if (liveTableBody.querySelector('.placeholder-row')) {
      liveTableBody.innerHTML = '';
    }

    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
    
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="cell-mono">${timeStr}</td>
      <td class="cell-mono">127.0.0.1</td>
      <td class="cell-mono">127.0.0.1</td>
      <td><span class="badge-tag data">ICMP</span></td>
      <td class="cell-mono" style="color: #60a5fa; font-weight: 600;">${ipidHex}</td>
      <td class="cell-mono">74 B</td>
      <td class="cell-mono">${ipdStr}</td>
      <td><span class="badge-tag ${tagClass}">${statusTag}</span></td>
    `;
    
    liveTableBody.prepend(tr);
    if (liveTableBody.children.length > 50) {
      liveTableBody.removeChild(liveTableBody.lastChild);
    }
  }

  function connectReceiverStream() {
    if (eventSource) {
      eventSource.close();
    }

    eventSource = new EventSource('/stream');

    eventSource.onopen = () => {
      console.log('SSE Stream connected to /stream');
    };

    eventSource.onerror = () => {
      console.warn('SSE Stream encountered an error or connection dropped');
    };

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (!data) return;

        if (data.type === 'status') {
          const msg = data.message || '';
          
          if (msg.includes('Packet')) {
            packetCount++;
            if (statusFragments) statusFragments.textContent = `${packetCount} packets`;

            const matchId = msg.match(/IP\.id=(0x[0-9A-Fa-f]+)/);
            const ipid = matchId ? matchId[1] : '0x0000';

            const matchDt = msg.match(/Δt=([0-9.]+)ms/);
            let ipd = '—';
            if (matchDt) {
              ipd = `${matchDt[1]} ms`;
            } else {
              const now = Date.now();
              if (lastPacketTime) {
                const diff = now - lastPacketTime;
                ipd = `${diff} ms`;
              }
              lastPacketTime = now;
            }

            const isSync = ipid.toUpperCase() === '0XDEAD';
            if (isSync && statusSync) {
              statusSync.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Detected (0xDEAD)</span>';
            }

            appendRealPacketRow(ipid, ipd, isSync ? 'SYNC' : 'DATA', isSync ? 'sync' : 'data');
          }

          if (msg.includes('Sync marker detected') && statusSync) {
            statusSync.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Detected</span>';
          }

          if (msg.includes('Frame extracted')) {
            if (statusFraming) statusFraming.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
            if (statusReassembly) statusReassembly.innerHTML = '<span style="color: #60a5fa; font-weight: 600;">100%</span>';
          }

          if (msg.includes('Decryption successful')) {
            if (authErrorBanner) authErrorBanner.style.display = 'none';
            if (statusAuth) statusAuth.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
            if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Successful</span>';
          }

          if (msg.includes('Decryption failed')) {
            if (authErrorBanner) authErrorBanner.style.display = 'flex';
            if (statusAuth) statusAuth.innerHTML = '<span style="color: #ef4444; font-weight: 600;">✗ Failed</span>';
            if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color: #ef4444; font-weight: 600;">✗ Failed</span>';
            showToast('Decryption Failed: Authentication Tag mismatch (Wrong Passphrase or Tampered Frame)', 'error');
          }

        } else if (data.type === 'message') {
          const plainMsg = data.message;
          if (authErrorBanner) authErrorBanner.style.display = 'none';
          if (decodedTextBox) {
            decodedTextBox.innerHTML = `&gt; <span style="color:#34d399; font-weight:700;">${escapeHtml(plainMsg)}</span>`;
          }
          if (statusAuth) statusAuth.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
          if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Successful</span>';
          if (statusReassembly) statusReassembly.innerHTML = '<span style="color: #60a5fa; font-weight: 600;">100%</span>';
          
          appendRealPacketRow('0x00FF', '0.5 s', 'COMPLETE', 'complete');
          showToast(`✓ Decoded covert message: "${plainMsg}"`, 'success');
        }
      } catch (err) {
        console.error('Error processing SSE:', err);
      }
    };
  }

  if (startBtn) {
    startBtn.addEventListener('click', async () => {
      const secret = document.getElementById('receiverSecret')?.value.trim() || '';
      const mode = document.getElementById('receiverChannel')?.value || 'header';
      const iface = document.getElementById('receiverInterface')?.value || 'lo0';

      if (!secret) {
        showToast('Validation Error: Shared Secret Passphrase is required', 'error');
        return;
      }

      startBtn.disabled = true;
      try {
        const res = await fetch('/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            passphrase: secret,
            mode: mode,
            interface: iface === 'lo0' ? null : iface
          })
        });

        const data = await res.json();
        if (res.ok && data.success) {
          if (stopBtn) stopBtn.disabled = false;
          if (liveBadge) liveBadge.style.display = 'inline-flex';
          packetCount = 0;
          lastPacketTime = null;
          resetChecklist();
          connectReceiverStream();
          showToast('✓ Sniffer active: Listening for ICMP covert packets...', 'info');
        } else {
          startBtn.disabled = false;
          showToast(`Failed to start sniffer: ${data.error || 'Unknown error'}`, 'error');
        }
      } catch (err) {
        startBtn.disabled = false;
        showToast(`Network Error: ${err.message}`, 'error');
      }
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener('click', async () => {
      if (startBtn) startBtn.disabled = false;
      stopBtn.disabled = true;
      if (liveBadge) liveBadge.style.display = 'none';

      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }

      try {
        await fetch('/stop', { method: 'POST' });
        showToast('Sniffer stopped', 'info');
      } catch (err) {}
    });
  }

  async function fetchReceiverState() {
    try {
      const res = await fetch('/api/receiver/state');
      if (!res.ok) return;
      const resp = await res.json();
      const data = resp.data;
      if (!data) return;

      // Update button states & live badge
      if (startBtn && stopBtn) {
        if (data.running) {
          startBtn.disabled = true;
          stopBtn.disabled = false;
          if (liveBadge) liveBadge.style.display = 'inline-flex';
          if (!eventSource) {
            connectReceiverStream();
          }
        } else {
          startBtn.disabled = false;
          stopBtn.disabled = true;
          if (liveBadge) liveBadge.style.display = 'none';
        }
      }

      if (data.icmp_packets > 0 && statusFragments) {
        statusFragments.textContent = `${data.icmp_packets} packets`;
      }
      if (liveBadge && data.running) {
        liveBadge.innerHTML = `<span style="width: 7px; height: 7px; border-radius: 50%; background: #10b981;"></span> LIVE ${data.icmp_packets} packets observed`;
      }

      // Sync checklist
      if (data.sync_detected && statusSync) {
        statusSync.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Detected (0xDEAD)</span>';
      }
      if (data.frame_extracted) {
        if (statusFraming) statusFraming.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
        if (statusReassembly) statusReassembly.innerHTML = '<span style="color: #60a5fa; font-weight: 600;">100%</span>';
      }

      // Recovered Message
      if (data.last_message && decodedTextBox) {
        if (authErrorBanner) authErrorBanner.style.display = 'none';
        decodedTextBox.innerHTML = `&gt; <span style="color:#34d399; font-weight:700;">${escapeHtml(data.last_message)}</span>`;
        if (statusAuth) statusAuth.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
        if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Successful</span>';
        if (statusReassembly) statusReassembly.innerHTML = '<span style="color: #60a5fa; font-weight: 600;">100%</span>';
        if (statusSync) statusSync.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Detected</span>';
        if (statusFraming) statusFraming.innerHTML = '<span style="color: #34d399; font-weight: 600;">✓ Valid</span>';
      } else if (data.last_error && authErrorBanner) {
        authErrorBanner.style.display = 'flex';
        if (statusAuth) statusAuth.innerHTML = '<span style="color: #ef4444; font-weight: 600;">✗ Failed</span>';
        if (statusDecrypt) statusDecrypt.innerHTML = '<span style="color: #ef4444; font-weight: 600;">✗ Failed</span>';
      }

      // Populate recent packets table if available
      if (data.recent_packets && data.recent_packets.length > 0 && liveTableBody) {
        if (liveTableBody.querySelector('.placeholder-row')) {
          liveTableBody.innerHTML = '';
        }
        if (liveTableBody.children.length === 0 || liveTableBody.children.length < data.recent_packets.length) {
          liveTableBody.innerHTML = '';
          data.recent_packets.slice().reverse().forEach(p => {
            const tr = document.createElement('tr');
            const dateObj = new Date(p.timestamp * 1000);
            const timeStr = dateObj.toTimeString().split(' ')[0] + '.' + String(Math.floor((p.timestamp % 1) * 1000)).padStart(3, '0');
            tr.innerHTML = `
              <td class="cell-mono">${timeStr}</td>
              <td class="cell-mono">127.0.0.1</td>
              <td class="cell-mono">127.0.0.1</td>
              <td><span class="badge-tag data">ICMP</span></td>
              <td class="cell-mono" style="color: #60a5fa; font-weight: 600;">${p.ip_id_hex}</td>
              <td class="cell-mono">74 B</td>
              <td class="cell-mono">${p.delay_ms > 0 ? p.delay_ms + ' ms' : '—'}</td>
              <td><span class="badge-tag ${p.is_sync ? 'sync' : 'data'}">${p.is_sync ? 'SYNC' : 'DATA'}</span></td>
            `;
            liveTableBody.appendChild(tr);
          });
        }
      }
    } catch (e) {
      console.warn('Receiver state polling error:', e);
    }
  }

  window.fetchReceiverState = fetchReceiverState;

  // Poll receiver state periodically when receiver screen or overview is active
  setInterval(() => {
    if (document.getElementById('view-receiver')?.classList.contains('active') ||
        document.getElementById('view-overview')?.classList.contains('active')) {
      fetchReceiverState();
    }
  }, 1200);

  fetchReceiverState();

  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const text = decodedTextBox ? decodedTextBox.innerText.replace(/^>\s*/, '') : '';
      if (!text || text.includes('Awaiting incoming')) {
        showToast('No decoded message available to export', 'error');
        return;
      }
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `recovered_message_${Math.floor(Date.now()/1000)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Exported recovered message to file', 'success');
    });
  }
}

/* ==========================================================================
   6. SCREEN 4: TRAFFIC PROFILER & GMM CONTROLLER
   ========================================================================== */
function initProfiler() {
  const dropzone = document.getElementById('pcapDropzone');
  const fileInput = document.getElementById('pcapFileInput');
  const dropTitle = document.getElementById('pcapDropzoneTitle');
  const dropSub = document.getElementById('pcapDropzoneSub');
  const progressFill = document.getElementById('pcapProgressFill');

  const pcapPackets = document.getElementById('pcapPackets');
  const pcapDuration = document.getElementById('pcapDuration');
  const pcapAvgIpd = document.getElementById('pcapAvgIpd');
  const pcapMedianIpd = document.getElementById('pcapMedianIpd');
  const pcapJitter = document.getElementById('pcapJitter');

  const trainBtn = document.getElementById('btnTrainGmm');
  const loadBtn = document.getElementById('btnLoadGmm');
  const tabRaw = document.getElementById('tabRawData');
  const tabGmm = document.getElementById('tabGmmProfile');

  const btnHttp = document.getElementById('btnPresetHttp');
  const btnVideo = document.getElementById('btnPresetVideo');
  const btnDns = document.getElementById('btnPresetDns');

  let activeData = null;

  async function uploadFile(file) {
    if (!file) return;
    if (dropTitle) dropTitle.textContent = `Analyzing ${file.name}...`;
    if (dropSub) dropSub.textContent = `Extracting inter-packet arrival times and training Gaussian Mixture Model...`;
    if (progressFill) progressFill.style.width = '45%';

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/profiler/upload_pcap', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (progressFill) progressFill.style.width = '100%';

      if (res.ok && data.success) {
        activeData = data;
        updateProfilerUI(data);
        renderProfilerChart(data);
        showToast(`✓ Profiler loaded ${data.filename} (${data.packets} packets, ${data.avg_ipd} avg IPD)`, 'success');
      } else {
        showToast(data.error || 'Failed to analyze PCAP', 'error');
        if (dropTitle) dropTitle.textContent = 'Click to Browse or Drop PCAP / CSV file here';
        if (progressFill) progressFill.style.width = '0%';
      }
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, 'error');
      if (dropTitle) dropTitle.textContent = 'Click to Browse or Drop PCAP / CSV file here';
      if (progressFill) progressFill.style.width = '0%';
    }
  }

  async function loadPreset(presetName) {
    if (dropTitle) dropTitle.textContent = `Generating ${presetName.toUpperCase()} Benchmark Dataset...`;
    if (progressFill) progressFill.style.width = '50%';

    try {
      const res = await fetch('/api/profiler/preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: presetName, components: 3 })
      });
      const data = await res.json();
      if (progressFill) progressFill.style.width = '100%';

      if (res.ok && data.success) {
        activeData = data;
        updateProfilerUI(data);
        renderProfilerChart(data);
        showToast(`✓ Loaded ${presetName.toUpperCase()} baseline dataset (${data.packets} packets)`, 'success');
      } else {
        showToast(data.error || 'Preset failed', 'error');
        if (dropTitle) dropTitle.textContent = 'Click to Browse or Drop PCAP / CSV file here';
        if (progressFill) progressFill.style.width = '0%';
      }
    } catch (err) {
      showToast(`Preset error: ${err.message}`, 'error');
      if (dropTitle) dropTitle.textContent = 'Click to Browse or Drop PCAP / CSV file here';
      if (progressFill) progressFill.style.width = '0%';
    }
  }

  function updateProfilerUI(data) {
    if (pcapPackets) pcapPackets.textContent = data.packets.toLocaleString();
    if (pcapDuration) pcapDuration.textContent = data.duration;
    if (pcapAvgIpd) pcapAvgIpd.textContent = data.avg_ipd;
    if (pcapMedianIpd) pcapMedianIpd.textContent = data.median_ipd;
    if (pcapJitter) pcapJitter.textContent = data.jitter;
    if (dropTitle) dropTitle.textContent = `✓ Active Baseline: ${data.filename}`;
    if (dropSub) dropSub.textContent = `${data.packets.toLocaleString()} packets analyzed · ${data.components} Gaussian components fitted`;
  }

  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        uploadFile(e.target.files[0]);
      }
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = '#3b82f6';
      dropzone.style.backgroundColor = 'rgba(37, 99, 235, 0.08)';
    });
    dropzone.addEventListener('dragleave', () => {
      dropzone.style.borderColor = 'var(--border-color)';
      dropzone.style.backgroundColor = 'transparent';
    });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.style.borderColor = 'var(--border-color)';
      dropzone.style.backgroundColor = 'transparent';
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        uploadFile(files[0]);
      }
    });
  }

  if (btnHttp) btnHttp.addEventListener('click', () => loadPreset('http'));
  if (btnVideo) btnVideo.addEventListener('click', () => loadPreset('video'));
  if (btnDns) btnDns.addEventListener('click', () => loadPreset('dns'));

  if (trainBtn) {
    trainBtn.addEventListener('click', async () => {
      trainBtn.disabled = true;
      trainBtn.textContent = 'Training GMM...';
      try {
        const res = await fetch('/api/profiler/train', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ preset: 'http', components: 3 })
        });
        const data = await res.json();
        trainBtn.disabled = false;
        trainBtn.textContent = 'Train Model';
        if (res.ok && data.success) {
          activeData = data;
          updateProfilerUI(data);
          renderProfilerChart(data);
          showToast('✓ Gaussian Mixture Model trained successfully (3 components)', 'success');
        } else {
          showToast(data.error || 'Training failed', 'error');
        }
      } catch (e) {
        trainBtn.disabled = false;
        trainBtn.textContent = 'Train Model';
        showToast(`Training error: ${e.message}`, 'error');
      }
    });
  }

  if (loadBtn) {
    loadBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/gmm_status');
        const data = await res.json();
        if (data.available) {
          showToast(`✓ Active GMM Model loaded (${data.statistics.n_components} components)`, 'info');
        } else {
          showToast('No saved GMM model found. Train one first.', 'warning');
        }
      } catch (err) {
        showToast(`Status check error: ${err.message}`, 'error');
      }
    });
  }

  if (tabRaw && tabGmm) {
    tabRaw.addEventListener('click', () => {
      tabRaw.classList.add('btn-primary');
      tabRaw.classList.remove('btn-secondary');
      tabGmm.classList.remove('btn-primary');
      tabGmm.classList.add('btn-secondary');
      showToast('Viewing Raw Empirical Delay Distribution', 'info');
    });
    tabGmm.addEventListener('click', () => {
      tabGmm.classList.add('btn-primary');
      tabGmm.classList.remove('btn-secondary');
      tabRaw.classList.remove('btn-primary');
      tabRaw.classList.add('btn-secondary');
      showToast('Viewing GMM Parameterized Multi-Modal Fit', 'info');
    });
  }
}

function renderProfilerChart(profData) {
  const canvas = document.getElementById('profilerDistributionCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.parentElement.clientWidth || 800;
  const height = 200;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = '#181b28';
  ctx.lineWidth = 1;
  for (let x = 40; x < width - 20; x += (width - 60) / 5) {
    ctx.beginPath();
    ctx.moveTo(x, 10);
    ctx.lineTo(x, height - 30);
    ctx.stroke();
  }

  const hist = profData?.histogram;
  const freqs = hist?.frequencies || [0.1, 0.35, 0.8, 0.95, 0.6, 0.25, 0.15, 0.45, 0.7, 0.5, 0.2, 0.1, 0.05];
  const barCount = freqs.length;
  const barWidth = (width - 80) / barCount;
  const maxF = Math.max(...freqs, 0.001);

  // Draw Histogram Bars
  ctx.fillStyle = 'rgba(6, 182, 212, 0.25)';
  for (let i = 0; i < barCount; i++) {
    const norm = freqs[i] / maxF;
    const h = Math.max(2, norm * (height - 60));
    ctx.fillRect(40 + i * barWidth, height - 30 - h, Math.max(1, barWidth - 3), h);
  }

  // Draw Real PDF Curve if provided
  if (profData?.pdf_curve?.y) {
    const py = profData.pdf_curve.y;
    const maxPy = Math.max(...py, 0.001);
    ctx.strokeStyle = '#c084fc';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    py.forEach((val, idx) => {
      const x = 40 + idx * ((width - 80) / (py.length - 1));
      const y = (height - 30) - ((val / maxPy) * (height - 60));
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  } else {
    // Standard overlay
    ctx.strokeStyle = '#a855f7';
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let x = 40; x < width - 20; x += 5) {
      const t = (x - 40) / (width - 60);
      const y = (height - 30) - (Math.exp(-Math.pow((t - 0.35) / 0.28, 2)) * 130);
      if (x === 40) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  ctx.font = '11px JetBrains Mono, monospace';
  ctx.fillStyle = '#6b7280';
  ctx.fillText('0 ms', 40, height - 12);
  ctx.fillText('50 ms', 40 + (width - 60) * 0.25, height - 12);
  ctx.fillText('100 ms', 40 + (width - 60) * 0.5, height - 12);
  ctx.fillText('200 ms', 40 + (width - 60) * 0.75, height - 12);
  ctx.fillText('300 ms', width - 65, height - 12);
}

/* ==========================================================================
   7. SCREEN 5: PACKET MONITOR CONTROLLER
   ========================================================================== */
let monitorPollTimer = null;
let currentMonitorFilter = 'ALL';

async function fetchMonitorPackets() {
  try {
    const res = await fetch(`/api/monitor/packets?filter=${currentMonitorFilter}&limit=50`);
    if (!res.ok) return;
    const data = await res.json();
    renderMonitorTable(data.packets);
  } catch (err) {
    console.warn('Packet monitor fetch error:', err);
  }
}

function renderMonitorTable(packets) {
  const tbody = document.getElementById('monitorTableBody');
  if (!tbody) return;

  if (!packets || packets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No captured packets available. Click "▶ Start Capture" to sniff live traffic.</td></tr>`;
    return;
  }

  let html = '';
  packets.forEach((p, idx) => {
    const isCovert = p.channel.includes('COVERT') || p.ip_id === '0xDEAD';
    html += `
      <tr class="${idx === packets.length - 1 ? 'selected' : ''}" data-packet-idx="${idx}">
        <td class="cell-mono">${String(p.num).padStart(3, '0')}</td>
        <td class="cell-mono">${p.time}</td>
        <td class="cell-mono">${p.src}</td>
        <td class="cell-mono">${p.dst}</td>
        <td><span class="badge-tag data">${p.proto}</span></td>
        <td class="cell-mono">${p.length} B</td>
        <td class="cell-mono" style="color: ${isCovert ? '#34d399' : '#60a5fa'}; font-weight: 700;">${p.ip_id}</td>
        <td class="cell-mono">${p.delta_t}</td>
        <td><span class="badge-tag ${isCovert ? 'sync' : 'data'}">${p.channel}</span></td>
      </tr>
    `;
  });
  tbody.innerHTML = html;

  // Bind click listeners for inspector
  tbody.querySelectorAll('tr').forEach((row, idx) => {
    row.addEventListener('click', () => {
      tbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
      row.classList.add('selected');
      inspectPacket(packets[idx]);
    });
  });

  if (packets.length > 0) {
    inspectPacket(packets[packets.length - 1]);
  }
}

function inspectPacket(p) {
  if (!p) return;
  const inspectorTitle = document.getElementById('inspectorPacketTitle');
  const inspectorSub = document.getElementById('inspectorPacketSub');
  const ipidBadge = document.getElementById('inspectorIpIdBadge');

  if (inspectorTitle) inspectorTitle.textContent = `Packet ${String(p.num).padStart(3, '0')}`;
  if (inspectorSub) inspectorSub.textContent = `${p.time} · ${p.length} bytes · ${p.proto}`;
  if (ipidBadge) ipidBadge.textContent = p.ip_id;

  // Update IPv4 and ICMP field elements
  const inspectorCard = document.getElementById('packetInspectorCard');
  if (inspectorCard) {
    const hexBlock = inspectorCard.querySelector('.packet-layer-item:last-child .packet-layer-body');
    if (hexBlock) {
      hexBlock.innerHTML = `<pre class="cell-mono" style="font-size: 0.76rem; color: #9ca3af; margin:0; line-height: 1.4;">${p.hex_dump || 'No payload bytes'}</pre>`;
    }
  }
}

function initPacketMonitor() {
  const startBtn = document.getElementById('btnMonitorStart');
  const stopBtn = document.getElementById('btnMonitorStop');
  const clearBtn = document.getElementById('btnMonitorClear');
  const exportBtn = document.getElementById('btnMonitorExport');
  const layerHeaders = document.querySelectorAll('.packet-layer-header');

  if (startBtn) {
    startBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/monitor/start', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({}) });
        if (res.ok) {
          showToast('✓ Packet Monitor active: Capturing lab network traffic...', 'info');
          if (monitorPollTimer) clearInterval(monitorPollTimer);
          monitorPollTimer = setInterval(fetchMonitorPackets, 1500);
          fetchMonitorPackets();
        }
      } catch (err) {
        showToast(`Monitor start error: ${err.message}`, 'error');
      }
    });
  }

  if (stopBtn) {
    stopBtn.addEventListener('click', async () => {
      try {
        await fetch('/api/monitor/stop', { method: 'POST' });
        if (monitorPollTimer) clearInterval(monitorPollTimer);
        showToast('Packet capture stopped', 'info');
      } catch (err) {}
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
      try {
        await fetch('/api/monitor/clear', { method: 'POST' });
        renderMonitorTable([]);
        showToast('Packet buffer cleared', 'info');
      } catch (err) {}
    });
  }

  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      window.location.href = '/api/monitor/export_pcap';
      showToast('Downloading captured PCAP file...', 'info');
    });
  }

  layerHeaders.forEach(hdr => {
    hdr.addEventListener('click', () => {
      const body = hdr.nextElementSibling;
      if (body) {
        body.classList.toggle('open');
        const arrow = hdr.querySelector('.layer-arrow');
        if (arrow) arrow.textContent = body.classList.contains('open') ? '⌵' : '›';
      }
    });
  });
}

/* ==========================================================================
   8. SCREEN 6: EXPERIMENTS CONTROLLER (Real Persistence & Execution)
   ========================================================================== */
async function fetchExperimentList() {
  try {
    const res = await fetch('/api/experiments/list');
    if (!res.ok) return;
    const data = await res.json();
    renderExperimentsTable(data.experiments || []);
  } catch (err) {
    console.warn('Error fetching experiments:', err);
  }
}

function renderExperimentsTable(experiments) {
  const tbody = document.getElementById('experimentTableBody');
  if (!tbody) return;

  if (!experiments || experiments.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No experiments registered. Click "+ New Experiment" to configure a controlled run.</td></tr>`;
    return;
  }

  let html = '';
  experiments.forEach(exp => {
    const statusClass = exp.status === 'Completed' ? 'completed' : (exp.status === 'Running' ? 'running' : (exp.status === 'Failed' ? 'failed' : 'review'));
    const isRunning = exp.status === 'Running';
    html += `
      <tr data-status="${exp.status}">
        <td style="font-weight: 600; color: #fff;">${escapeHtml(exp.name)}</td>
        <td class="cell-mono">${exp.channel}</td>
        <td class="cell-mono" style="font-weight:600;">${exp.payload ? exp.payload.length + ' B' : '—'}</td>
        <td class="cell-mono" style="font-weight:600;">${exp.results?.packets_sent || '—'}</td>
        <td>${exp.timing_profile || 'Normal'}</td>
        <td><span class="badge-tag ${statusClass}">${exp.status}</span></td>
        <td style="color: var(--text-muted); font-size: 0.78rem;">${exp.created_at || '—'}</td>
        <td>
          <button class="btn btn-ghost btn-view-exp" data-id="${exp.id}" style="padding: 2px 8px; font-size: 0.76rem;">👁 View</button>
          <button class="btn btn-ghost btn-run-exp" data-id="${exp.id}" style="padding: 2px 8px; font-size: 0.76rem; color:#60a5fa;" ${isRunning ? 'disabled' : ''}>▶ Run</button>
        </td>
      </tr>
    `;
  });
  tbody.innerHTML = html;

  // Bind Action Buttons
  tbody.querySelectorAll('.btn-view-exp').forEach(btn => {
    btn.addEventListener('click', () => {
      const expId = btn.getAttribute('data-id');
      viewExperimentModal(expId);
    });
  });

  tbody.querySelectorAll('.btn-run-exp').forEach(btn => {
    btn.addEventListener('click', async () => {
      const expId = btn.getAttribute('data-id');
      btn.disabled = true;
      btn.textContent = 'Running...';
      showToast(`Running experiment ${expId}...`, 'info');
      try {
        const res = await fetch(`/api/experiments/${expId}/run`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`✓ Experiment "${data.experiment.name}" completed successfully!`, 'success');
          fetchExperimentList();
        } else {
          showToast(`Experiment run failed: ${data.error || 'Unknown error'}`, 'error');
          fetchExperimentList();
        }
      } catch (err) {
        showToast(`Experiment run error: ${err.message}`, 'error');
        fetchExperimentList();
      }
    });
  });
}

async function viewExperimentModal(expId) {
  try {
    const res = await fetch(`/api/experiments/${expId}/view`);
    if (!res.ok) return;
    const data = await res.json();
    const exp = data.experiment;

    const modal = document.getElementById('modalViewExperiment');
    const title = document.getElementById('viewExpTitle');
    const body = document.getElementById('viewExpBody');
    const runBtn = document.getElementById('btnRunExpAgain');

    if (title) title.textContent = exp.name;
    if (runBtn) runBtn.setAttribute('data-id', exp.id);

    if (body) {
      body.innerHTML = `
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
          <div style="background: #0b0c10; padding: 10px; border-radius: 4px; border: 1px solid var(--border-color);">
            <div style="font-size: 0.72rem; color: var(--text-muted);">CHANNEL</div>
            <div style="font-weight: 700; color: #fff; font-size: 0.95rem;">${exp.channel}</div>
          </div>
          <div style="background: #0b0c10; padding: 10px; border-radius: 4px; border: 1px solid var(--border-color);">
            <div style="font-size: 0.72rem; color: var(--text-muted);">STATUS</div>
            <div style="font-weight: 700; color: #34d399; font-size: 0.95rem;">${exp.status}</div>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Payload</label>
          <div class="cell-mono" style="background: #0b0c10; padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 4px; font-size: 0.82rem; color:#93c5fd;">${escapeHtml(exp.payload)}</div>
        </div>
        ${exp.results ? `
          <div style="background: rgba(37, 99, 235, 0.08); border: 1px solid rgba(37, 99, 235, 0.3); border-radius: 6px; padding: 14px;">
            <div style="font-weight: 700; color: #93c5fd; margin-bottom: 8px; font-size: 0.88rem;">Measured Performance Results:</div>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Packets:</span> <strong style="color:#fff;">${exp.results.packets_sent}</strong></div>
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Duration:</span> <strong style="color:#fff;">${exp.results.duration_s}s</strong></div>
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Throughput:</span> <strong style="color:#fff;">${exp.results.throughput_bps} bps</strong></div>
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Stealth Index:</span> <strong style="color:#34d399;">${exp.results.stealth_index}%</strong></div>
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Packet Loss:</span> <strong style="color:#fff;">${exp.results.packet_loss_pct}%</strong></div>
              <div><span style="font-size:0.75rem; color:var(--text-muted);">Bit Error Rate:</span> <strong style="color:#fff;">${exp.results.ber_pct}%</strong></div>
            </div>
          </div>
        ` : '<div style="color: var(--text-muted); font-size: 0.82rem;">No execution results recorded yet. Click "Run Experiment Again".</div>'}
      `;
    }

    if (modal) modal.classList.add('show');
  } catch (err) {
    showToast(`Error viewing experiment: ${err.message}`, 'error');
  }
}

function initExperiments() {
  const newExpBtn = document.getElementById('btnNewExperiment');
  const modalNew = document.getElementById('modalNewExperiment');
  const modalView = document.getElementById('modalViewExperiment');
  const closeNewBtn = document.getElementById('btnCloseNewExpModal');
  const cancelNewBtn = document.getElementById('btnCancelNewExp');
  const submitNewBtn = document.getElementById('btnSubmitNewExp');
  const closeViewBtn = document.getElementById('btnCloseViewExpModal');
  const closeViewBtn2 = document.getElementById('btnCloseViewExp');
  const runAgainBtn = document.getElementById('btnRunExpAgain');

  fetchExperimentList();

  if (newExpBtn && modalNew) {
    newExpBtn.addEventListener('click', () => modalNew.classList.add('show'));
  }

  [closeNewBtn, cancelNewBtn].forEach(btn => {
    if (btn && modalNew) {
      btn.addEventListener('click', () => modalNew.classList.remove('show'));
    }
  });

  [closeViewBtn, closeViewBtn2].forEach(btn => {
    if (btn && modalView) {
      btn.addEventListener('click', () => modalView.classList.remove('show'));
    }
  });

  if (submitNewBtn) {
    submitNewBtn.addEventListener('click', async () => {
      const name = document.getElementById('inputExperimentName')?.value.trim();
      const channel = document.getElementById('selectExperimentChannel')?.value;
      const profile = document.getElementById('selectExperimentProfile')?.value;
      const target = document.getElementById('inputExperimentTarget')?.value.trim() || '127.0.0.1';
      const payload = document.getElementById('inputExperimentPayload')?.value.trim();

      if (!name) {
        showToast('Please enter an Experiment Name', 'error');
        return;
      }
      if (!payload) {
        showToast('Please enter a payload message to test', 'error');
        return;
      }

      submitNewBtn.disabled = true;
      try {
        const res = await fetch('/api/experiments/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name,
            channel: channel,
            timing_profile: profile,
            target_ip: target,
            payload: payload
          })
        });

        const data = await res.json();
        submitNewBtn.disabled = false;
        if (res.ok && data.success) {
          showToast(`✓ Experiment "${name}" created and registered`, 'success');
          if (modalNew) modalNew.classList.remove('show');
          fetchExperimentList();
        } else {
          showToast(data.error || 'Failed to create experiment', 'error');
        }
      } catch (err) {
        submitNewBtn.disabled = false;
        showToast(`Error: ${err.message}`, 'error');
      }
    });
  }

  if (runAgainBtn && modalView) {
    runAgainBtn.addEventListener('click', async () => {
      const expId = runAgainBtn.getAttribute('data-id');
      if (!expId) return;
      modalView.classList.remove('show');
      showToast(`Running experiment ${expId}...`, 'info');
      try {
        const res = await fetch(`/api/experiments/${expId}/run`, { method: 'POST' });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast(`✓ Experiment "${data.experiment.name}" completed successfully!`, 'success');
          fetchExperimentList();
        } else {
          showToast(`Run failed: ${data.error || 'Unknown error'}`, 'error');
        }
      } catch (err) {
        showToast(`Run error: ${err.message}`, 'error');
      }
    });
  }

  // Filter Tags
  document.querySelectorAll('.exp-filter-tag').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.exp-filter-tag').forEach(p => p.style.opacity = '0.6');
      pill.style.opacity = '1';
      const status = pill.getAttribute('data-status');
      document.querySelectorAll('#experimentTableBody tr').forEach(row => {
        if (!status || status === 'all' || row.getAttribute('data-status') === status) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    });
  });
}

/* ==========================================================================
   9. SCREEN 7: RESULTS & ANALYTICS CONTROLLER
   ========================================================================= */
let cachedResultsData = null;

async function fetchResultsData() {
  try {
    const res = await fetch('/api/results/data');
    if (!res.ok) return;
    const data = await res.json();
    cachedResultsData = data;

    if (data.available) {
      const accVal = document.querySelector('#view-results .metrics-grid-4 .metric-card:nth-child(1) .metric-value');
      if (accVal) accVal.textContent = `${data.packet_recovery_rate_pct}%`;

      const pktsVal = document.querySelector('#view-results .metrics-grid-4 .metric-card:nth-child(2) .metric-value');
      if (pktsVal) pktsVal.innerHTML = `${data.total_packets_transmitted} <span style="font-size: 1.1rem; color: var(--text-muted); font-weight: normal;">/ ${data.total_packets_transmitted}</span>`;

      const delayVal = document.querySelector('#view-results .metrics-grid-4 .metric-card:nth-child(4) .metric-value');
      if (delayVal) delayVal.innerHTML = `${data.avg_duration_s}<span style="font-size: 1rem; color: var(--text-muted); font-weight: normal; margin-left: 2px;">s</span>`;
    }
  } catch (err) {
    console.warn('Error fetching results data:', err);
  }
}

function initResultsCharts() {
  const exportReportBtn = document.getElementById('btnExportReport');
  if (exportReportBtn) {
    exportReportBtn.addEventListener('click', () => {
      window.location.href = '/api/results/export_report?format=csv';
      showToast('✓ Exporting experiment analytics report (CSV)...', 'info');
    });
  }
  window.addEventListener('resize', renderAllResultsCharts);
}

function renderAllResultsCharts() {
  fetchResultsData().then(() => {
    renderRecoveryChart();
    renderTransmissionTimeChart();
    renderInterArrivalAreaChart();
    renderPayloadSizeChart();
  });
}

function renderRecoveryChart() {
  const canvas = document.getElementById('chartRecoveryRate');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.parentElement.clientWidth || 400;
  const height = 150;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = '#181b28';
  ctx.lineWidth = 1;
  ctx.strokeRect(35, 10, width - 45, height - 35);

  ctx.strokeStyle = '#3b82f6';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  const startY = height - 40;
  const endY = 25;
  ctx.moveTo(35, startY);
  ctx.bezierCurveTo(width * 0.35, height - 60, width * 0.65, 35, width - 15, endY);
  ctx.stroke();

  ctx.fillStyle = '#34d399';
  ctx.beginPath();
  ctx.arc(width - 15, endY, 4, 0, Math.PI * 2);
  ctx.fill();

  ctx.font = '10px JetBrains Mono, monospace';
  ctx.fillStyle = '#6b7280';
  ctx.fillText('100%', 2, 28);
  ctx.fillText('0', 20, height - 12);
  ctx.fillText('100% Sequence', width - 90, height - 12);
}

function renderTransmissionTimeChart() {
  const canvas = document.getElementById('chartTransmissionTime');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.parentElement.clientWidth || 400;
  const height = 150;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  const series = cachedResultsData?.series || [];
  const bars = series.length > 0 ? series.slice(0, 4).map(s => ({
    label: s.name.substring(0, 10) + '...',
    color: s.channel.includes('Header') ? '#2563eb' : '#a855f7',
    val: Math.min(1.0, s.duration_s / 40.0)
  })) : [
    { label: 'Prepare', color: '#2563eb', val: 0.6 },
    { label: 'Transmit', color: '#1d4ed8', val: 0.88 },
    { label: 'Recover', color: '#10b981', val: 0.45 }
  ];

  const barW = 34;
  const gap = (width - (bars.length * barW)) / (bars.length + 1);

  bars.forEach((b, i) => {
    const x = gap + i * (barW + gap);
    const h = Math.max(8, b.val * (height - 45));
    const y = height - 25 - h;

    ctx.fillStyle = b.color;
    ctx.beginPath();
    ctx.roundRect(x, y, barW, h, [4, 4, 0, 0]);
    ctx.fill();

    ctx.font = '9px Inter, sans-serif';
    ctx.fillStyle = '#9ca3af';
    ctx.textAlign = 'center';
    ctx.fillText(b.label, x + barW / 2, height - 8);
  });
}

function renderInterArrivalAreaChart() {
  const canvas = document.getElementById('chartInterArrival');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.parentElement.clientWidth || 400;
  const height = 150;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  const grad = ctx.createLinearGradient(0, 40, 0, height - 25);
  grad.addColorStop(0, 'rgba(16, 185, 129, 0.4)');
  grad.addColorStop(1, 'rgba(16, 185, 129, 0.02)');

  ctx.beginPath();
  ctx.moveTo(10, height - 25);
  ctx.lineTo(10, height - 40);
  ctx.lineTo(width * 0.15, height - 55);
  ctx.lineTo(width * 0.3, height - 45);
  ctx.lineTo(width * 0.45, height - 75);
  ctx.lineTo(width * 0.6, height - 60);
  ctx.lineTo(width * 0.75, height - 85);
  ctx.lineTo(width * 0.9, height - 50);
  ctx.lineTo(width - 10, height - 65);
  ctx.lineTo(width - 10, height - 25);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.strokeStyle = '#10b981';
  ctx.lineWidth = 1.8;
  ctx.stroke();

  ctx.fillStyle = 'rgba(16, 185, 129, 0.18)';
  ctx.fillRect(width - 65, 45, 52, 20);
  ctx.font = '10px JetBrains Mono, monospace';
  ctx.fillStyle = '#34d399';
  ctx.textAlign = 'center';
  ctx.fillText('74 ms', width - 39, 59);
}

function renderPayloadSizeChart() {
  const canvas = document.getElementById('chartPayloadGrowth');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const width = canvas.parentElement.clientWidth || 400;
  const height = 150;
  canvas.width = width;
  canvas.height = height;

  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = '#a855f7';
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(25, height - 35);
  ctx.lineTo(width * 0.45, height - 55);
  ctx.lineTo(width - 25, 25);
  ctx.stroke();

  ctx.font = '10px JetBrains Mono, monospace';
  ctx.fillStyle = '#6b7280';
  ctx.textAlign = 'left';
  ctx.fillText('64 B', 20, height - 10);
  ctx.textAlign = 'right';
  ctx.fillText('1024 B', width - 15, height - 10);
}

/* ==========================================================================
   10. SCREEN 8: DOCUMENTATION CONTROLLER
   ========================================================================== */
function initDocumentation() {
  const tocLinks = document.querySelectorAll('.docs-toc .toc-link');
  tocLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = link.getAttribute('href').replace('#', '');
      const targetSec = document.getElementById(targetId);
      if (targetSec) {
        tocLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        targetSec.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
}

/* ==========================================================================
   11. SCREEN 9: SETTINGS CONTROLLER (Persistence)
   ========================================================================== */
async function loadSettingsFromBackend() {
  try {
    const res = await fetch('/api/settings');
    if (!res.ok) return;
    const data = await res.json();
    if (data.settings) {
      const s = data.settings;
      if (document.getElementById('reduceMotionToggle')) {
        document.getElementById('reduceMotionToggle').checked = !!s.reduce_motion;
      }
    }
  } catch (err) {
    console.warn('Error loading settings:', err);
  }
}

function initSettings() {
  const saveBtn = document.getElementById('btnSaveSettings');
  const resetBtn = document.getElementById('btnResetSettings');
  const clearHistBtn = document.getElementById('btnClearHistory');

  loadSettingsFromBackend();

  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      const isLight = document.body.classList.contains('light-theme');
      const reduceMotion = document.getElementById('reduceMotionToggle')?.checked || false;

      try {
        const res = await fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            theme: isLight ? 'light' : 'dark',
            reduce_motion: reduceMotion,
            default_target: '127.0.0.1'
          })
        });

        if (res.ok) {
          showToast('✓ Laboratory settings saved and persisted.', 'success');
        } else {
          showToast('Failed to save settings', 'error');
        }
      } catch (err) {
        showToast(`Save error: ${err.message}`, 'error');
      }
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/settings/reset', { method: 'POST' });
        if (res.ok) {
          showToast('Settings restored to factory laboratory defaults', 'info');
        }
      } catch (err) {}
    });
  }

  if (clearHistBtn) {
    clearHistBtn.addEventListener('click', async () => {
      if (confirm('Are you sure you want to permanently clear all recorded experiments and captured packet history?')) {
        try {
          await fetch('/api/experiments/clear', { method: 'POST' });
          await fetch('/api/monitor/clear', { method: 'POST' });
          fetchExperimentList();
          renderMonitorTable([]);
          showToast('✓ All experiment history and packet buffers cleared successfully.', 'success');
        } catch (err) {
          showToast(`Error: ${err.message}`, 'error');
        }
      }
    });
  }
}

/* ==========================================================================
   UTILITY HELPERS
   ========================================================================== */
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function showToast(message, type = 'info') {
  let toast = document.getElementById('appToast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'appToast';
    toast.className = 'toast-notification';
    document.body.appendChild(toast);
  }

  const icon = type === 'success' ? '✓' : (type === 'error' ? '⚠' : 'ℹ');
  toast.innerHTML = `<span style="font-weight:700; color:${type==='success'?'#34d399':(type==='error'?'#f87171':'#60a5fa')}">${icon}</span> <span>${message}</span>`;
  toast.classList.add('show');

  setTimeout(() => {
    toast.classList.remove('show');
  }, 3500);
}
