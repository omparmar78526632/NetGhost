"""
Generates a professionally styled Microsoft Word (.docx) document
for the NetGhost Comprehensive Technical Report & Project Documentation.
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

def create_report():
    doc = Document()
    
    # Page Setup: Standard Margins
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Color Palette
    PRIMARY = RGBColor(30, 58, 138)     # Deep Navy #1E3A8A
    SECONDARY = RGBColor(14, 116, 144)  # Cyan/Teal #0E7490
    TEXT_DARK = RGBColor(30, 41, 59)    # Slate #1E293B
    MUTED = RGBColor(100, 116, 139)     # Slate Muted #64748B
    ACCENT = RGBColor(180, 83, 9)       # Amber #B45309

    # Set Default Font
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = TEXT_DARK

    # --- Title & Metadata ---
    title_p = doc.add_paragraph()
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title_p.add_run("NETGHOST")
    title_run.font.name = 'Arial'
    title_run.font.size = Pt(26)
    title_run.font.bold = True
    title_run.font.color.rgb = PRIMARY

    subtitle_p = doc.add_paragraph()
    subtitle_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub_run = subtitle_p.add_run("Covert Data Communication Using Network Steganography and Traffic Modulation")
    sub_run.font.name = 'Arial'
    sub_run.font.size = Pt(14)
    sub_run.font.bold = True
    sub_run.font.color.rgb = SECONDARY

    meta_p = doc.add_paragraph()
    meta_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta_run = meta_p.add_run("Comprehensive Technical Report & Project Documentation\n")
    meta_run.font.size = Pt(11)
    meta_run.font.italic = True
    meta_run.font.color.rgb = MUTED

    meta_run2 = meta_p.add_run("Domain: Network Security | Applied Cryptography | Machine Learning\nProtocol: IPv4 / ICMP Echo Requests | Cipher: AES-256-GCM (PBKDF2 100k)")
    meta_run2.font.size = Pt(10)
    meta_run2.font.color.rgb = PRIMARY
    meta_run2.font.bold = True

    doc.add_paragraph().paragraph_format.space_after = Pt(12)

    def add_custom_heading(text, level=1):
        h = doc.add_heading(text, level=level)
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(6)
        run = h.runs[0]
        run.font.name = 'Arial'
        if level == 1:
            run.font.size = Pt(16)
            run.font.color.rgb = PRIMARY
            run.font.bold = True
        elif level == 2:
            run.font.size = Pt(13)
            run.font.color.rgb = SECONDARY
            run.font.bold = True
        return h

    # =========================================================================
    # 1. Executive Summary & Problem Statement
    # =========================================================================
    add_custom_heading("1. Executive Summary & Problem Statement", level=1)
    
    p = doc.add_paragraph()
    p.add_run("1.1 The Fundamental Security Problem\n").bold = True
    p.add_run(
        "Standard network security mechanisms such as TLS/HTTPS, IPsec, and VPNs are designed to protect "
        "data confidentiality (what is being said). However, modern enterprise firewalls, Intrusion Detection Systems (IDS), "
        "and Deep Packet Inspection (DPI) technologies continuously monitor traffic metadata. Even when traffic is encrypted, "
        "network surveillance can detect that communication is occurring, identify the communication endpoints, and perform traffic analysis.\n\n"
    )
    p.add_run("1.2 The NetGhost Solution\n").bold = True
    p.add_run(
        "NetGhost is an advanced Network Steganography research system that hides the very existence of a communication session. "
        "By leveraging ubiquitous ICMP Echo Request ('ping') packets that are typically permitted across corporate firewalls, "
        "NetGhost embeds encrypted covert data across two distinct channels:\n"
    )
    
    bp1 = doc.add_paragraph(style='List Bullet')
    bp1.add_run("Storage-Based Steganography (IP Header Channel): ").bold = True
    bp1.add_run("Embeds 16-bit chunks of encrypted data directly into the IPv4 Identification (IP.id) field, delivering high-speed transfer with zero payload alteration.")
    
    bp2 = doc.add_paragraph(style='List Bullet')
    bp2.add_run("Timing-Based Steganography (Temporal IPD Channel): ").bold = True
    bp2.add_run("Transmits packets with completely normal headers and empty payloads, modulating secret bits entirely into the Inter-Packet Delay (Δt) between consecutive packets.")

    # =========================================================================
    # 2. Covert Channel Mechanisms
    # =========================================================================
    add_custom_heading("2. Covert Channel Mechanisms & Timing Profiles", level=1)

    p = doc.add_paragraph()
    p.add_run("2.1 IP Header Channel (Storage Embedding)\n").bold = True
    p.add_run(
        "In IPv4, the 16-bit Identification field is historically used for packet fragmentation. NetGhost embeds 2 bytes (16 bits) "
        "per ICMP packet into this field. The receiver extracts the values in real time, synchronizes on the 0xDEAD marker, and reassembles "
        "the byte stream. This channel achieves high throughput (~8,000 bps) suitable for rapid file and text transfers.\n\n"
    )
    p.add_run("2.2 Temporal IPD Channel (Inter-Packet Delay Modulation)\n").bold = True
    p.add_run(
        "The Temporal channel hides data in the time interval between packets (Δt = t[current] - t[previous]). "
        "The receiver applies a 75.0 ms threshold classifier:\n"
        "• Bit 0: Decoded when Δt < 75.0 ms (Target center: ~25.0 ms)\n"
        "• Bit 1: Decoded when Δt ≥ 75.0 ms (Target center: ~125.0 ms)\n"
    )

    # Timing Profiles Table
    add_custom_heading("2.3 Timing Profiles Comparison", level=2)
    table = doc.add_table(rows=1, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = table.rows[0].cells
    headers = ["Profile", "Delay Generation Logic", "Stealth / IDS Resistance", "Primary Use Case"]
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        set_cell_background(hdr_cells[i], "1E3A8A")
        set_cell_margins(hdr_cells[i], 120, 120, 140, 140)

    profile_data = [
        ("Constant Delay", "Bit 0: Fixed 25.0 ms\nBit 1: Fixed 125.0 ms", "Low (Produces rigid spikes on inter-arrival histograms)", "Controlled laboratory testing & baseline benchmarks"),
        ("Variable Delay (Normal)", "Bit 0: 25ms ± 2ms Gaussian noise\nBit 1: 125ms ± 2ms Gaussian noise", "High (Mimics natural network jitter and router queuing)", "Evading signature-based statistical intrusion detection"),
        ("Gamma Profile", "Samples from Gamma distribution (k=2) centered around targets", "High (Mimics right-skewed asymmetric network buffer delays)", "Emulating congested enterprise network traffic"),
        ("GMM (Machine Learning)", "Samples from multi-modal Gaussian Mixture Model trained on PCAP", "Maximum (Indistinguishable from legitimate ambient traffic)", "Active evasion against advanced AI/ML network anomaly detectors")
    ]

    for row_idx, data in enumerate(profile_data):
        row_cells = table.add_row().cells
        bg_color = "F8FAFC" if row_idx % 2 == 0 else "FFFFFF"
        for c_idx, val in enumerate(data):
            row_cells[c_idx].text = val
            set_cell_background(row_cells[c_idx], bg_color)
            set_cell_margins(row_cells[c_idx], 100, 100, 120, 120)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # =========================================================================
    # 3. Cryptographic Pipeline & Payload Structure
    # =========================================================================
    add_custom_heading("3. Cryptographic Pipeline & Payload Slicing", level=1)
    
    p = doc.add_paragraph()
    p.add_run(
        "NetGhost guarantees absolute data confidentiality, integrity, and authenticity using military-grade "
        "AES-256-GCM authenticated encryption. Every transmission generates a fresh, multi-component encrypted payload:\n"
    )

    crypto_terms = [
        ("PBKDF2-HMAC-SHA256", "Key Derivation Function running 100,000 iterations to derive a 256-bit AES key from a passphrase and random Salt."),
        ("Salt (16 Bytes)", "Cryptographic random value (os.urandom(16)). Ensures the same password produces a unique AES key for every transmission, defeating rainbow table attacks."),
        ("Nonce (12 Bytes)", "Number used ONCE (os.urandom(12)). Acts as a unique initialization vector for AES-GCM, preventing identical plaintexts from yielding identical ciphertexts."),
        ("Ciphertext (Variable)", "The scrambled bytes produced by the AES cipher containing the secret message."),
        ("Auth Tag (16 Bytes)", "Galois/Counter Mode authentication seal. Validates that not a single bit was corrupted, dropped, or modified in transit.")
    ]

    for term, desc in crypto_terms:
        bp = doc.add_paragraph(style='List Bullet')
        bp.add_run(f"{term}: ").bold = True
        bp.add_run(desc)

    p_slice = doc.add_paragraph()
    p_slice.add_run("\nPayload Slicing in Python (common/crypto.py):\n").bold = True
    p_slice.add_run(
        "salt = encrypted_payload[:16]             # Bytes 0 to 15 (16B)\n"
        "nonce = encrypted_payload[16:28]          # Bytes 16 to 27 (12B)\n"
        "ciphertext_with_tag = encrypted_payload[28:] # Bytes 28 to End (Ciphertext + 16B Tag)\n"
    )
    p_slice.runs[1].font.name = 'Consolas'
    p_slice.runs[1].font.size = Pt(9.5)
    p_slice.runs[1].font.color.rgb = PRIMARY

    # =========================================================================
    # 4. Frame & Packet Structure: Concrete Walkthrough (Sending "h")
    # =========================================================================
    add_custom_heading("4. Frame & Packet Structure: Concrete Walkthrough (Sending 'h')", level=1)

    p = doc.add_paragraph()
    p.add_run("4.1 The 50-Byte Application Frame Layout\n").bold = True
    p.add_run("When the user transmits the single character 'h' (ASCII 0x68) with passphrase 'secret123':\n")

    frame_table = doc.add_table(rows=1, cols=4)
    frame_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    f_hdr = frame_table.rows[0].cells
    for i, title in enumerate(["Field Name", "Byte Size", "Sample Value", "Function & Purpose"]):
        f_hdr[i].text = title
        f_hdr[i].paragraphs[0].runs[0].font.bold = True
        f_hdr[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        set_cell_background(f_hdr[i], "0E7490")
        set_cell_margins(f_hdr[i], 100, 100, 120, 120)

    frame_data = [
        ("Sync Marker", "2 Bytes", "0xDEAD (57005)", "Unique magic number signaling transmission start to receiver"),
        ("Length Prefix", "2 Bytes", "0x002D (45 Dec)", "Explicitly declares 45 bytes of encrypted payload following"),
        ("Salt", "16 Bytes", "A4 F1 89 2C ...", "PBKDF2 key derivation randomizer"),
        ("Nonce", "12 Bytes", "3F C8 17 A9 ...", "AES-GCM one-time initialization vector"),
        ("Ciphertext", "1 Byte", "0x8F", "Encrypted representation of ASCII 'h' (0x68)"),
        ("Auth Tag", "16 Bytes", "E1 4C 90 7A ...", "Single 16-byte cryptographic seal covering the entire frame"),
        ("Zero Padding", "1 Byte", "0x00", "Pads frame from 45 to 46 bytes to ensure clean 16-bit word alignment")
    ]

    for r_idx, data in enumerate(frame_data):
        row_cells = frame_table.add_row().cells
        bg = "F0FDFA" if r_idx % 2 == 0 else "FFFFFF"
        for c_idx, val in enumerate(data):
            row_cells[c_idx].text = val
            set_cell_background(row_cells[c_idx], bg)
            set_cell_margins(row_cells[c_idx], 80, 80, 100, 100)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    p_ip = doc.add_paragraph()
    p_ip.add_run("4.2 IP Header Channel Transmission (25 Packets Total)\n").bold = True
    p_ip.add_run(
        "The 50 bytes are sliced into 25 sixteen-bit chunks inserted into packet[IP].id:\n"
        "• Packet 1: IP.id = 0xDEAD (57005) -> Sync Marker\n"
        "• Packet 2: IP.id = 0x002D (45) -> Length Prefix\n"
        "• Packets 3–10: IP.id = Salt Chunks (16 Bytes / 8 Chunks)\n"
        "• Packets 11–16: IP.id = Nonce Chunks (12 Bytes / 6 Chunks)\n"
        "• Packet 17: IP.id = Ciphertext (0x8F) + Auth Tag Byte 0\n"
        "• Packets 18–25: IP.id = Remaining 15 Auth Tag Bytes + Padding Byte (0x00)\n"
        "Total Time: ~0.25 seconds.\n\n"
    )

    p_temp = doc.add_paragraph()
    p_temp.add_run("4.3 Temporal Channel Transmission (401 Packets Total)\n").bold = True
    p_temp.add_run(
        "The 50 bytes are expanded into 400 binary bits (50 × 8 bits), transmitted via 401 packets:\n"
        "• Packet 1: Lead Reference Packet sent at t=0ms (starts receiver clock)\n"
        "• Packets 2–17 (16 bits): Sync Marker 0xDEAD ('11011110 10101101') sent via 125ms and 25ms delays\n"
        "• Packets 18–33 (16 bits): Length Prefix 45 ('00000000 00101101')\n"
        "• Packets 34–161 (128 bits): Salt bytes\n"
        "• Packets 162–257 (96 bits): Nonce bytes\n"
        "• Packets 258–265 (8 bits): Ciphertext 'h' (0x8F = '10001111')\n"
        "• Packets 266–393 (128 bits): 16-byte Auth Tag\n"
        "• Packets 394–401 (8 bits): Padding byte (0x00 = '00000000')\n"
        "Total Time: ~30 seconds.\n"
    )

    # =========================================================================
    # 5. Error Detection & Packet Loss Handling
    # =========================================================================
    add_custom_heading("5. Simplex Protocol Design & Packet Loss Handling", level=1)

    p = doc.add_paragraph()
    p.add_run("5.1 Why NetGhost Uses a Simplex (One-Way) Architecture\n").bold = True
    p.add_run(
        "Traditional protocols use two-way acknowledgments (ACKs). In network steganography, sending ACK packets back to the "
        "sender generates an observable return traffic pattern on firewalls and network monitors. NetGhost maintains absolute "
        "stealth by operating strictly unidirectionally.\n\n"
    )
    p.add_run("5.2 How Packet Loss is Caught Without Return ACKs\n").bold = True
    p.add_run(
        "1. IP Header Channel: If a packet drops, the receiver's chunk counter is short (e.g., 24/25 packets received). "
        "The frame remains at incomplete progress (96%).\n"
        "2. Temporal Channel: If a packet drops, two delay intervals merge into one (Δt = 25ms + 125ms = 150ms), causing a timing "
        "collapse, bitstream truncation (399/400 bits), and sync marker disruption.\n"
        "3. Cryptographic Fail-Safe: AES-256-GCM verifies the 16-byte Auth Tag. If even a single bit or byte is corrupted, missing, "
        "or shifted, decryption fails with an InvalidTag exception, completely preventing corrupted data from being decoded.\n"
    )

    # =========================================================================
    # 6. Team Contribution Matrix
    # =========================================================================
    add_custom_heading("6. Team Member Contribution & Module Division", level=1)

    team_table = doc.add_table(rows=1, cols=4)
    team_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_hdr = team_table.rows[0].cells
    for i, title in enumerate(["Member", "Designated Role", "Primary Modules", "Key Technical Contributions"]):
        t_hdr[i].text = title
        t_hdr[i].paragraphs[0].runs[0].font.bold = True
        t_hdr[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        set_cell_background(t_hdr[i], "1E3A8A")
        set_cell_margins(t_hdr[i], 100, 100, 120, 120)

    team_data = [
        ("Om", "Lead Architect", "sender/sender_core.py\nsender/sender_app.py\nstart_netghost.bat", "• End-to-end system architecture & channel selection\n• HeaderChannelSender (IP.id embedding)\n• TemporalChannelSender (timing modulation)\n• Raw Scapy socket crafting & Windows multimedia timer (timeBeginPeriod)"),
        ("Kedar N.", "Cryptography & Receiver Specialist", "receiver/receiver_core.py\ncommon/crypto.py\ncommon/framing.py\ntests/test_crypto.py", "• AES-256-GCM AEAD encryption/decryption engine\n• PBKDF2-HMAC-SHA256 (100k rounds) key derivation & framing (0xDEAD)\n• Real-time Scapy packet sniffer & deduplication filter\n• 75ms threshold temporal bit demodulator & Auth Tag validation"),
        ("Kedar P.", "Machine Learning Specialist", "ml/ml_profiler.py\nml/train_model.py\ntests/test_ml.py\ndata/", "• PCAP traffic timing extractor & feature parser\n• Gaussian Mixture Model (GMM) training with EM\n• Synthetic inter-packet delay sampling\n• Statistical traffic modeling (variance, entropy)"),
        ("Atharva", "Dashboard & QA Specialist", "app.py\ntemplates/\nstatic/\ntests/test_live_flow_events.py", "• Flask REST backend & Server-Sent Events (SSE /stream)\n• Cybernetic UI & Real-Time Flow Visualizer\n• IP-ID packet card conveyor & bit timeline\n• Full 53-suite automated test suite")
    ]

    for r_idx, data in enumerate(team_data):
        row_cells = team_table.add_row().cells
        bg = "F8FAFC" if r_idx % 2 == 0 else "FFFFFF"
        for c_idx, val in enumerate(data):
            row_cells[c_idx].text = val
            set_cell_background(row_cells[c_idx], bg)
            set_cell_margins(row_cells[c_idx], 80, 80, 100, 100)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # =========================================================================
    # 7. Viva & Project Evaluation Q&A Guide
    # =========================================================================
    add_custom_heading("7. Viva & Evaluation Q&A Guide", level=1)

    qa_list = [
        ("Q1: What is the core difference between Cryptography and Steganography?",
         "Cryptography conceals the content of a message, while Steganography conceals the existence of the communication itself. NetGhost combines both by first applying AES-256-GCM encryption and then embedding the ciphertext into covert network channels."),
        
        ("Q2: Why use ICMP Echo Requests (Ping) rather than TCP or UDP?",
         "ICMP is universally allowed through firewalls for network reachability diagnostics. Because it is connectionless, it avoids TCP three-way handshakes, ACKs, and retransmission timers that would interfere with timing steganography."),
        
        ("Q3: Why is there no return ACK packet from receiver to sender?",
         "In steganography, return ACK packets generate a detectable two-way traffic footprint on firewalls and network monitors. NetGhost uses a simplex (unidirectional) architecture and relies on the AES-256-GCM 16-byte Authentication Tag to guarantee 100% data integrity."),
        
        ("Q4: How does the Variable Delay profile evade statistical Intrusion Detection Systems (IDS)?",
         "Constant delays create two sharp, unnatural spikes on inter-arrival histograms that anomaly detectors flag immediately. Variable delay adds Gaussian random noise (±2ms), making covert timing blend naturally into real-world network jitter."),
        
        ("Q5: How does the Machine Learning (GMM) profile work?",
         "The GMM profile parses background PCAP captures to model the multi-modal probability density function of legitimate traffic. Delays are sampled directly from this distribution, allowing covert packets to match ambient network traffic patterns."),
        
        ("Q6: How is packet loss detected in the Temporal channel?",
         "A lost packet merges two timing intervals (Δt = 25ms + 125ms = 150ms). This distorts the decoded bits and causes a frame length mismatch. AES-256-GCM Authentication Tag validation immediately fails with an InvalidTag exception, rejecting any corrupt data.")
    ]

    for q, a in qa_list:
        qp = doc.add_paragraph()
        qp.add_run(f"{q}\n").bold = True
        qp.runs[0].font.color.rgb = PRIMARY
        qp.add_run(f"Answer: {a}\n")

    # Output paths
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "NETGHOST_TECHNICAL_REPORT.docx")
    fallback_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs", "NETGHOST_PROJECT_DOCUMENTATION.docx")
    try:
        doc.save(output_path)
        print(f"Successfully generated: {output_path}")
    except PermissionError:
        doc.save(fallback_path)
        print(f"Primary file was open in Word. Successfully generated: {fallback_path}")

if __name__ == "__main__":
    create_report()
