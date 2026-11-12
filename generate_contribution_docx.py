"""
Generates a Microsoft Word (.docx) document for the NetGhost Team Contribution & Technical Division.
"""

import os
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, hex_color):
    """Set background color of a table cell."""
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading_elm)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner padding for a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def create_contribution_doc():
    doc = Document()
    
    # Page Setup
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Color Palette
    PRIMARY = RGBColor(30, 58, 138)     # Navy #1E3A8A
    SECONDARY = RGBColor(14, 116, 144)  # Cyan/Teal #0E7490
    TEXT_DARK = RGBColor(30, 41, 59)    # Slate #1E293B
    MUTED = RGBColor(100, 116, 139)     # Muted #64748B

    # Normal font
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = TEXT_DARK

    # Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run("NETGHOST")
    r_title.font.name = 'Arial'
    r_title.font.size = Pt(26)
    r_title.font.bold = True
    r_title.font.color.rgb = PRIMARY

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_sub = p_sub.add_run("Project Contribution & Technical Division Document")
    r_sub.font.name = 'Arial'
    r_sub.font.size = Pt(15)
    r_sub.font.bold = True
    r_sub.font.color.rgb = SECONDARY

    p_meta = doc.add_paragraph()
    p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_meta = p_meta.add_run(
        "Domain: Network Security | Network Steganography | Applied Cryptography | Machine Learning\n"
        "Project Team: Om Parmar, Atharva, Kedar P., Kedar N.\n"
        "Protocol Stack: IPv4, ICMP Echo Requests (Type 8), AES-256-GCM, PBKDF2, Scapy"
    )
    r_meta.font.size = Pt(10)
    r_meta.font.color.rgb = MUTED

    doc.add_paragraph().paragraph_format.space_after = Pt(14)

    def add_custom_heading(text, level=1):
        h = doc.add_heading(text, level=level)
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(6)
        run = h.runs[0]
        run.font.name = 'Arial'
        if level == 1:
            run.font.size = Pt(15)
            run.font.color.rgb = PRIMARY
            run.font.bold = True
        elif level == 2:
            run.font.size = Pt(13)
            run.font.color.rgb = SECONDARY
            run.font.bold = True
        return h

    # Section 1
    add_custom_heading("1. Executive Project Summary", level=1)
    p_exec = doc.add_paragraph()
    p_exec.add_run(
        "NetGhost is an advanced network steganography laboratory system that enables invisible, covert data transmission "
        "over computer networks. Unlike conventional encryption (e.g., standard TLS/HTTPS or VPN tunnels) which conceals only "
        "message content while leaving observable communication metadata, NetGhost hides the very existence of the communication session.\n\n"
        "The system leverages legitimate ICMP Echo Request ('ping') packets across two distinct channels:\n"
    )
    bp1 = doc.add_paragraph(style='List Bullet')
    bp1.add_run("Storage-Based Steganography (IP Header Channel): ").bold = True
    bp1.add_run("Embeds encrypted 16-bit chunks directly into the IPv4 Identification (IP.id) header field (~8,000 bps throughput).")
    
    bp2 = doc.add_paragraph(style='List Bullet')
    bp2.add_run("Timing-Based Steganography (Temporal IPD Channel): ").bold = True
    bp2.add_run("Modulates inter-packet arrival times (Δt) between consecutive packets without altering packet headers or payloads, evading Deep Packet Inspection (DPI).")

    # Section 2
    add_custom_heading("2. Team Contribution Summary Matrix", level=1)
    
    table = doc.add_table(rows=1, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_hdr = table.rows[0].cells
    for i, title in enumerate(["Member Name", "Official Role", "Primary Modules & Files", "Key Technical Contributions"]):
        t_hdr[i].text = title
        t_hdr[i].paragraphs[0].runs[0].font.bold = True
        t_hdr[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        set_cell_background(t_hdr[i], "1E3A8A")
        set_cell_margins(t_hdr[i], 100, 100, 120, 120)

    team_data = [
        ("Om Parmar", "Lead Architect &\nTransmission Specialist", "sender/sender_core.py\nsender/sender_app.py\nstart_netghost.bat\nstart_dual_nodes.bat\nstart_sender.bat", 
         "• End-to-end architecture & dual-node network design\n• HeaderChannelSender (IPv4 IP.id embedding)\n• TemporalChannelSender (Inter-Packet Delay modulation)\n• Raw Scapy socket crafting & packet injection\n• Windows multimedia timer (timeBeginPeriod)"),
        
        ("Kedar N.", "Cryptography &\nReceiver Specialist", "common/crypto.py\ncommon/framing.py\ncommon/utils.py\nreceiver/receiver_core.py\nreceiver/receiver_app.py\ntests/test_crypto.py\ntests/test_framing.py",
         "• AES-256-GCM AEAD encryption/decryption engine\n• PBKDF2-HMAC-SHA256 (100k rounds) key derivation\n• Binary framing protocol (0xDEAD sync + length header)\n• Scapy real-time packet sniffer & deduplication engine\n• 75ms threshold temporal bit demodulator & reassembly\n• 16-byte Auth Tag validation & tamper detection"),
        
        ("Kedar P.", "Machine Learning &\nTraffic Profiling Specialist", "ml/ml_profiler.py\nml/train_model.py\ntests/test_ml.py\ndata/ (PCAPs & Models)",
         "• PCAP traffic timing extractor & inter-arrival calculation\n• Statistical profiling (variance, skewness, entropy)\n• Gaussian Mixture Model (GMM) training via EM algorithm\n• Synthetic timing delay sampling to evade statistical IDS\n• Gamma distribution router queue modeling (np.random.gamma)"),
        
        ("Atharva", "Full-Stack Dashboard,\nFlow Visualizer & QA", "app.py\ntemplates/index.html\nstatic/css/netghost.css\nstatic/js/netghost.js\ntests/test_live_flow_events.py\ntests/test_temporal_channel.py",
         "• Flask REST API & Server-Sent Events (SSE /stream)\n• Multi-host URL routing & node isolation (5000 vs 5001)\n• Cybernetic Lab Dashboard UI design & responsiveness\n• Real-Time Flow Visualizer: IP-ID packet conveyor, temporal timeline, and typewriter plaintext terminal\n• Automated test suite (53 passing unit & integration tests)")
    ]

    for r_idx, data in enumerate(team_data):
        row_cells = table.add_row().cells
        bg = "F8FAFC" if r_idx % 2 == 0 else "FFFFFF"
        for c_idx, val in enumerate(data):
            row_cells[c_idx].text = val
            set_cell_background(row_cells[c_idx], bg)
            set_cell_margins(row_cells[c_idx], 80, 80, 100, 100)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # Section 3: Detailed Breakdown
    add_custom_heading("3. Detailed Individual Responsibilities & Technical Work", level=1)

    details = [
        ("3.1 Om Parmar — Lead Architect & Transmission Specialist", [
            ("System Architecture & Network Protocol Design", "Designed the end-to-end communication protocol, defining how application-layer encrypted frames are mapped down to Network Layer (Layer 3 IPv4) raw packets. Implemented the dual-node architecture allowing the Sender and Receiver to run as separate network endpoints on different host ports (Port 5000 and Port 5001)."),
            ("Covert Sender Core Engine (sender/sender_core.py)", "Engineered the IP Header Channel (HeaderChannelSender) slicing 50-byte encrypted frames into 16-bit chunks for IPv4 Identification insertion. Engineered the Temporal IPD Channel (TemporalChannelSender) converting binary bitstreams into precise microsecond sleep delays."),
            ("Low-Level Socket & Hardware Timer Engineering", "Integrated Scapy for raw IP/ICMP packet crafting and direct network transmission. Resolved Windows timer resolution limitations by interfacing with Windows multimedia timer APIs (ctypes.windll.winmm.timeBeginPeriod(1)) to guarantee 1ms timer precision required for reliable temporal modulation."),
            ("Deployment & Automation Scripts", "Authored automated batch execution scripts (start_netghost.bat, start_dual_nodes.bat, start_sender.bat) with automatic administrator privilege validation and virtual environment activation.")
        ]),
        
        ("3.2 Kedar N. — Cryptography & Receiver Specialist", [
            ("Cryptographic Security Engine (common/crypto.py)", "Implemented military-grade AES-256-GCM (Galois/Counter Mode) authenticated encryption (AEAD), ensuring complete confidentiality and tamper detection. Developed PBKDF2-HMAC-SHA256 key derivation executing 100,000 hashing rounds with a 16-byte random Salt to defeat rainbow table attacks. Implemented 12-byte random Nonce initialization to guarantee unique ciphertext generation across identical messages."),
            ("Framing Protocol & Serialization (common/framing.py, common/utils.py)", "Designed the binary framing layout: 2-byte Sync Marker (0xDEAD) + 2-byte Length Header + Encrypted Payload + Word Alignment Padding. Created byte-to-uint16, uint16-to-byte, byte-to-bit, and bit-to-byte conversion utilities with big-endian network byte ordering."),
            ("Receiver Core Engine (receiver/receiver_core.py)", "Built the multi-adapter packet sniffing engine with Npcap loopback auto-resolution and deduplication filtering (<3ms deduplication window). Implemented the 75ms threshold demodulator converting packet arrival intervals (Δt) into binary 0s (<75ms) and 1s (≥75ms). Developed the frame reassembly engine that synchronizes on 0xDEAD, validates expected frame length, and extracts payload bytes."),
            ("Integrity Validation & Error Recovery", "Implemented cryptographic tag validation using AES-GCM. Corrupted, dropped, or swapped packets immediately raise InvalidTag, preventing corrupted plaintext display.")
        ]),

        ("3.3 Kedar P. — Machine Learning & Traffic Profiling Specialist", [
            ("PCAP Traffic Feature Extraction (ml/ml_profiler.py)", "Engineered the network packet capture analyzer to extract timestamps and inter-packet arrival times (Δt) from raw PCAP/PCAPNG files. Implemented statistical data cleaning, removing anomalous network outliers and zero-delay packet bursts."),
            ("Statistical Modeling & Anomaly Metrics", "Implemented statistical estimators calculating mean, variance, standard deviation, skewness, kurtosis, and Shannon entropy over packet inter-arrival times."),
            ("Gaussian Mixture Model (GMM) Training (ml/train_model.py)", "Trained multi-modal Gaussian Mixture Models using the Expectation-Maximization (EM) algorithm (via scikit-learn) to fit the empirical timing distribution of ambient enterprise traffic. Generated persistent model artifacts (gmm_timing.pkl) storing Gaussian component weights, means, and covariances."),
            ("Traffic Modulation & Queue Latency Modeling", "Developed conditional probability sampling (sample_bit_delay) allowing the sender to generate synthetic delays directly from the trained GMM distribution. Implemented the Gamma Distribution profile (np.random.gamma(shape=2.0, scale=target/2.0)), mathematically modeling asymmetric router buffer queuing delays to evade statistical Intrusion Detection Systems (IDS).")
        ]),

        ("3.4 Atharva — Full-Stack Dashboard, Real-Time Flow Visualizer & QA Specialist", [
            ("Backend Architecture & Streaming Pipeline (app.py)", "Developed the Flask REST API architecture providing preparation, transmission, reception, and state query endpoints. Implemented multi-client Server-Sent Events (SSE /stream) broadcasting real-time packet transmissions and receptions directly to the browser. Engineered node role detection and URL isolation (/sender on port 5000 and /receiver on port 5001), ensuring strict separation between sender and receiver workspaces."),
            ("Cybernetic Frontend & User Experience (templates/, static/)", "Designed the responsive Cybernetic Laboratory UI with dark/light themes, custom CSS design system, and accessibility compliance. Implemented client-side controllers for form validation, key management, and asynchronous REST interactions."),
            ("Real-Time Data Transfer Flow Visualizer", "Built the LIVE TRANSMISSION FLOW panel: animated 5-stage pipeline nodes, dynamic link particles, live metrics, and real-time IP-ID packet card conveyor. Built the LIVE RECEPTION FLOW panel: 7-stage reception pipeline, 75ms threshold timeline with sampled delay badges, diagnostic counters, and typewriter plaintext reveal terminal."),
            ("Quality Assurance & Automated Testing Suite (tests/)", "Authored and maintained the automated test suite comprising 53 unit and integration tests (all passing) across cryptographic operations, framing protocols, header channels, temporal modulation, ML profiling, and live SSE event callbacks.")
        ])
    ]

    for member_title, subtasks in details:
        add_custom_heading(member_title, level=2)
        for task_title, task_desc in subtasks:
            p_task = doc.add_paragraph(style='List Bullet')
            p_task.add_run(f"{task_title}: ").bold = True
            p_task.add_run(task_desc)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # Section 4: Deliverables Table
    add_custom_heading("4. Summary Table of Project Deliverables", level=1)
    
    deliv_table = doc.add_table(rows=1, cols=3)
    deliv_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    d_hdr = deliv_table.rows[0].cells
    for i, title in enumerate(["Functional Area", "Deliverable Description", "Primary Contributors"]):
        d_hdr[i].text = title
        d_hdr[i].paragraphs[0].runs[0].font.bold = True
        d_hdr[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        set_cell_background(d_hdr[i], "0E7490")
        set_cell_margins(d_hdr[i], 100, 100, 120, 120)

    deliv_data = [
        ("Transmission Engine", "IP Header (IP.id) Embedding & Temporal IPD Modulation Engine", "Om Parmar"),
        ("Cryptographic Pipeline", "AES-256-GCM AEAD, PBKDF2 (100k rounds), Framing & Tamper Seal", "Kedar N."),
        ("Sniffing & Decoding", "Raw Scapy Sniffer, 75ms Threshold Demodulator & Frame Reassembler", "Kedar N."),
        ("Machine Learning", "PCAP Parser, GMM Model Training (EM), Gamma Queue Modeling", "Kedar P."),
        ("Web Dashboard & API", "Flask REST Backend, Multi-Host Isolation & SSE Event Pipeline", "Atharva"),
        ("Live Visualizer UI", "Real-Time Flow Pipeline, Conveyor Cards & Typewriter Terminal", "Atharva"),
        ("Testing & Verification", "53 Automated Pytest Test Suites & End-to-End Validation", "Atharva & Kedar N."),
        ("Deployment Scripts", "Windows Admin Launchers (start_dual_nodes.bat, start_sender.bat)", "Om Parmar")
    ]

    for r_idx, data in enumerate(deliv_data):
        row_cells = deliv_table.add_row().cells
        bg = "F0FDFA" if r_idx % 2 == 0 else "FFFFFF"
        for c_idx, val in enumerate(data):
            row_cells[c_idx].text = val
            set_cell_background(row_cells[c_idx], bg)
            set_cell_margins(row_cells[c_idx], 80, 80, 100, 100)

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    # Section 5: Viva Talking Points
    add_custom_heading("5. Individual Viva Talking Points", level=1)

    viva_points = [
        ("Om Parmar (Lead Architect & Transmission Specialist)",
         "\"I designed the system architecture, dual-node execution model, and the sender transmission engine. I implemented the raw Scapy packet generation for both the 16-bit IPv4 Identification channel and the Temporal Inter-Packet Delay channel, ensuring sub-millisecond sleep precision using Windows multimedia timers.\""),
        
        ("Kedar N. (Cryptography & Receiver Specialist)",
         "\"I developed the cryptographic security pipeline and the receiver demodulation engine. I implemented AES-256-GCM authenticated encryption, PBKDF2 key derivation, binary frame synchronization on 0xDEAD, packet sniffing with loopback deduplication, and the 75ms threshold decoding algorithm.\""),
        
        ("Kedar P. (Machine Learning & Traffic Profiling Specialist)",
         "\"I developed the machine learning and traffic profiling modules. I extracted timing distributions from real network PCAPs, trained multi-modal Gaussian Mixture Models using scikit-learn, and implemented the Gamma distribution queue model so covert packet timings match natural router buffer delays to evade detection.\""),
        
        ("Atharva (Full-Stack Dashboard, Flow Visualizer & QA Specialist)",
         "\"I built the full-stack web dashboard, Flask REST backend, and Server-Sent Events live streaming pipeline. I created the Real-Time Flow Visualizer showing live packet conveyor cards, temporal timelines, and typewriter plaintext reveals, along with the complete 53-suite automated testing framework.\"")
    ]

    for member, speech in viva_points:
        p_viva = doc.add_paragraph()
        p_viva.add_run(f"• {member}:\n").bold = True
        p_viva.runs[0].font.color.rgb = PRIMARY
        p_viva.add_run(f"  {speech}\n")

    # Output path
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "NETGHOST_TEAM_CONTRIBUTION.docx")
    fallback_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "NETGHOST_CONTRIBUTION_DOCUMENT.docx")
    try:
        doc.save(output_path)
        print(f"Successfully generated: {output_path}")
    except PermissionError:
        doc.save(fallback_path)
        print(f"Primary file open. Successfully generated: {fallback_path}")

if __name__ == "__main__":
    create_contribution_doc()
