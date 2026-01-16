"""
Digital Signature Verification System with RSA and QRIS
Aplikasi Streamlit untuk membuat dan memverifikasi tanda tangan digital
"""

import streamlit as st
from io import BytesIO
import base64

# Import modules
from crypto.rsa_utils import (
    f20221310104_generate_key_pair,
    f20221310104_export_public_key,
    f20221310104_export_private_key,
    f20221310104_import_public_key
)
from crypto.signature import f20221310104_sign_message, f20221310104_verify_signature, f20221310104_get_hash_hex
from qris.qr_generator import f20221310104_create_signature_qris, f20221310104_decode_qris_data, f20221310104_qris_to_bytes

# Page configuration
st.set_page_config(
    page_title="Digital Signature & QRIS",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS untuk tampilan menarik
st.markdown("""
<style>
    /* Import font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    /* Main container styling */
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
    }
    
    /* Global text color fix */
    .stApp, .stApp p, .stApp span, .stApp label, .stApp div {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* Markdown text */
    .stMarkdown, .stMarkdown p, .stMarkdown span, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4 {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* Labels */
    .stTextArea label, .stTextInput label, .stSelectbox label, .stRadio label, .stCheckbox label {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* Radio button text */
    .stRadio > div > label > div > p {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    .stRadio [data-baseweb="radio"] {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* File uploader */
    .stFileUploader label, .stFileUploader span, .stFileUploader p {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    [data-testid="stFileUploader"] {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    [data-testid="stFileUploader"] section {
        background: rgba(255,255,255,0.05) !important;
        border: 1px dashed rgba(255,255,255,0.3) !important;
        border-radius: 12px !important;
    }
    
    [data-testid="stFileUploader"] section span, [data-testid="stFileUploader"] section small {
        color: rgba(255, 255, 255, 0.7) !important;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: rgba(255,255,255,0.05) !important;
        border-radius: 12px !important;
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    .streamlit-expanderHeader p, .streamlit-expanderHeader span {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    [data-testid="stExpander"] {
        background: rgba(30, 30, 50, 0.95) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 12px !important;
    }
    
    /* Expander header/summary - all states */
    [data-testid="stExpander"] summary {
        background: rgba(102, 126, 234, 0.15) !important;
        color: rgba(255, 255, 255, 0.95) !important;
        border-radius: 12px !important;
    }
    
    [data-testid="stExpander"] summary:hover {
        background: rgba(102, 126, 234, 0.25) !important;
        color: rgba(255, 255, 255, 1) !important;
    }
    
    [data-testid="stExpander"] summary:focus,
    [data-testid="stExpander"] summary:active,
    [data-testid="stExpander"] summary:focus-visible {
        background: rgba(102, 126, 234, 0.3) !important;
        color: rgba(255, 255, 255, 1) !important;
        outline: none !important;
        box-shadow: none !important;
    }
    
    [data-testid="stExpander"] summary span,
    [data-testid="stExpander"] summary p,
    [data-testid="stExpander"] summary div {
        color: rgba(255, 255, 255, 0.95) !important;
        background: transparent !important;
    }
    
    /* Override any white backgrounds on expander elements */
    [data-testid="stExpander"] * {
        background-color: transparent;
    }
    
    [data-testid="stExpander"] > details {
        background: rgba(30, 30, 50, 0.95) !important;
        border-radius: 12px !important;
    }
    
    [data-testid="stExpander"] > details > summary {
        background: rgba(102, 126, 234, 0.15) !important;
    }
    
    [data-testid="stExpander"] > details > summary:hover,
    [data-testid="stExpander"] > details > summary:focus,
    [data-testid="stExpander"] > details > summary:active {
        background: rgba(102, 126, 234, 0.25) !important;
    }
    
    [data-testid="stExpander"] > details[open] > summary {
        background: rgba(102, 126, 234, 0.2) !important;
        border-radius: 12px 12px 0 0 !important;
    }
    
    /* Expander content - dark background */
    [data-testid="stExpander"] > div {
        background: transparent !important;
    }
    
    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background: rgba(0, 0, 0, 0.2) !important;
        border-radius: 0 0 12px 12px !important;
        padding: 1rem !important;
    }
    
    [data-testid="stExpander"] [data-testid="stExpanderDetails"] > div {
        background: transparent !important;
    }
    
    /* Code blocks */
    .stCodeBlock, .stCodeBlock > div, code, pre {
        background: rgba(0, 0, 0, 0.4) !important;
        color: #e2e8f0 !important;
    }
    
    [data-testid="stCodeBlock"] {
        background: rgba(0, 0, 0, 0.4) !important;
    }
    
    [data-testid="stCodeBlock"] > div {
        background: rgba(0, 0, 0, 0.4) !important;
    }
    
    [data-testid="stCodeBlock"] pre {
        background: rgba(0, 0, 0, 0.4) !important;
        color: #e2e8f0 !important;
    }
    
    [data-testid="stCodeBlock"] code {
        background: transparent !important;
        color: #e2e8f0 !important;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
        border-right: 1px solid rgba(255,255,255,0.1);
    }
    
    [data-testid="stSidebar"] .stRadio > label {
        color: white !important;
        font-weight: 500;
    }
    
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span, [data-testid="stSidebar"] label {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.5rem;
        font-weight: 700;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    
    .sub-header {
        color: rgba(255,255,255,0.7) !important;
        text-align: center;
        font-size: 1rem;
        margin-bottom: 2rem;
    }
    
    /* Card styling */
    .custom-card {
        background: rgba(255,255,255,0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        padding: 1.5rem;
        border: 1px solid rgba(255,255,255,0.1);
        margin-bottom: 1rem;
    }
    
    .card-title {
        color: #667eea !important;
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white !important;
        border: none;
        border-radius: 12px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
    }
    
    .stButton > button:disabled {
        background: rgba(255,255,255,0.1) !important;
        color: rgba(255,255,255,0.4) !important;
    }
    
    /* Success/Error boxes */
    .success-box {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        border-radius: 12px;
        padding: 1rem;
        color: white !important;
        text-align: center;
        font-weight: 600;
        margin: 1rem 0;
    }
    
    .error-box {
        background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        border-radius: 12px;
        padding: 1rem;
        color: white !important;
        text-align: center;
        font-weight: 600;
        margin: 1rem 0;
    }
    
    /* Streamlit alerts */
    [data-testid="stAlert"] {
        background: rgba(255,255,255,0.1) !important;
        border: 1px solid rgba(255,255,255,0.2) !important;
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    [data-testid="stAlert"] p {
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    /* Text area styling */
    .stTextArea textarea {
        background: rgba(30, 30, 50, 0.9) !important;
        border: 1px solid rgba(255,255,255,0.3) !important;
        border-radius: 12px !important;
        color: #ffffff !important;
        caret-color: #ffffff !important;
    }
    
    .stTextArea textarea::placeholder {
        color: rgba(255,255,255,0.5) !important;
    }
    
    [data-testid="stTextArea"] textarea {
        background: rgba(30, 30, 50, 0.9) !important;
        color: #ffffff !important;
        caret-color: #ffffff !important;
    }
    
    [data-testid="stTextArea"] {
        color: #ffffff !important;
    }
    
    [data-testid="stTextArea"] > div > div > textarea {
        background: rgba(30, 30, 50, 0.9) !important;
        color: #ffffff !important;
    }
    
    .stTextInput input {
        background: rgba(30, 30, 50, 0.9) !important;
        border: 1px solid rgba(255,255,255,0.3) !important;
        border-radius: 12px !important;
        color: #ffffff !important;
        caret-color: #ffffff !important;
    }
    
    .stTextInput input::placeholder {
        color: rgba(255,255,255,0.5) !important;
    }
    
    [data-testid="stTextInput"] input {
        background: rgba(30, 30, 50, 0.9) !important;
        color: #ffffff !important;
        caret-color: #ffffff !important;
    }
    
    /* Info box */
    .info-box {
        background: rgba(102, 126, 234, 0.2);
        border-left: 4px solid #667eea;
        border-radius: 0 12px 12px 0;
        padding: 1rem;
        margin: 1rem 0;
        color: rgba(255, 255, 255, 0.9) !important;
    }
    
    .info-box strong, .info-box code {
        color: rgba(255, 255, 255, 0.95) !important;
    }
    
    /* QRIS container */
    .qris-container {
        background: white;
        border-radius: 16px;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    }
    
    /* Key display */
    .key-display {
        background: rgba(0,0,0,0.3);
        border-radius: 8px;
        padding: 0.5rem;
        font-family: 'Courier New', monospace;
        font-size: 0.75rem;
        color: #a0aec0 !important;
        max-height: 150px;
        overflow-y: auto;
        word-break: break-all;
    }
    
    /* Image caption */
    [data-testid="stImage"] > div > div > p {
        color: rgba(255, 255, 255, 0.7) !important;
    }
    
    /* Download button */
    .stDownloadButton > button {
        background: linear-gradient(90deg, #11998e 0%, #38ef7d 100%) !important;
        color: white !important;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    /* Divider */
    .custom-divider {
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
        margin: 2rem 0;
    }
    
    /* Step indicators */
    .step-indicator {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 50%;
        color: white !important;
        font-weight: 600;
        font-size: 0.85rem;
        margin-right: 0.5rem;
    }
    
    /* Spinner */
    .stSpinner > div {
        color: rgba(255, 255, 255, 0.9) !important;
    }
</style>
""", unsafe_allow_html=True)


def f20221310104_sender_page():
    """Halaman Pengirim - Generate kunci dan tanda tangan digital"""
    
    st.markdown('<h1 class="main-header">🔐 Pengirim Pesan</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Generate kunci RSA, tanda tangani pesan, dan buat QRIS</p>', unsafe_allow_html=True)
    
    # Initialize session state
    if 'private_key' not in st.session_state:
        st.session_state.private_key = None
    if 'public_key' not in st.session_state:
        st.session_state.public_key = None
    if 'signature' not in st.session_state:
        st.session_state.signature = None
    if 'qris_image' not in st.session_state:
        st.session_state.qris_image = None
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Step 1: Generate Keys
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">
                <span class="step-indicator">1</span>
                Generate Kunci RSA
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🔑 Generate Pasangan Kunci RSA", key="gen_keys"):
            with st.spinner("Generating RSA key pair..."):
                private_key, public_key = f20221310104_generate_key_pair(2048)
                st.session_state.private_key = private_key
                st.session_state.public_key = public_key
                st.session_state.private_key_pem = f20221310104_export_private_key(private_key)
                st.session_state.public_key_pem = f20221310104_export_public_key(public_key)
            st.success("✅ Kunci RSA berhasil di-generate!")
        
        if st.session_state.private_key is not None:
            with st.expander("📄 Lihat Public Key", expanded=False):
                st.code(st.session_state.public_key_pem, language="text")
            
            with st.expander("🔒 Lihat Private Key (Rahasia!)", expanded=False):
                st.code(st.session_state.private_key_pem, language="text")
        
        st.markdown('<div class="custom-divider"></div>', unsafe_allow_html=True)
        
        # Step 2: Input Message
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">
                <span class="step-indicator">2</span>
                Masukkan Pesan
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        message = st.text_area(
            "Pesan yang akan ditandatangani:",
            placeholder="Ketik pesan Anda di sini...",
            height=120,
            key="message_input"
        )
        
        if message:
            hash_value = f20221310104_get_hash_hex(message)
            st.markdown(f"""
            <div class="info-box">
                <strong>📊 SHA-256 Hash:</strong><br>
                <code style="font-size: 0.8rem; word-break: break-all;">{hash_value}</code>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        # Step 3: Sign Message
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">
                <span class="step-indicator">3</span>
                Tanda Tangani & Generate QRIS
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        can_sign = st.session_state.private_key is not None and message
        
        if st.button("✍️ Tanda Tangani Pesan & Buat QRIS", disabled=not can_sign, key="sign_btn"):
            with st.spinner("Signing message and generating QRIS..."):
                # Sign the message
                signature = f20221310104_sign_message(message, st.session_state.private_key)
                st.session_state.signature = signature
                
                # Generate QRIS
                qris_image = f20221310104_create_signature_qris(
                    message,
                    signature,
                    st.session_state.public_key_pem
                )
                st.session_state.qris_image = qris_image
            
            st.success("✅ Pesan berhasil ditandatangani!")
        
        if st.session_state.signature:
            with st.expander("🔏 Lihat Digital Signature", expanded=False):
                st.code(st.session_state.signature, language="text")
        
        # Display QRIS
        if st.session_state.qris_image:
            st.markdown('<div class="custom-divider"></div>', unsafe_allow_html=True)
            
            st.markdown("""
            <div class="custom-card">
                <div class="card-title">
                    📱 QRIS Digital Signature
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Convert image to bytes for display
            img_buffer = BytesIO()
            st.session_state.qris_image.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Display QRIS
            st.image(img_buffer, caption="QRIS berisi Digital Signature", use_container_width=True)
            
            # Download button
            qris_bytes = f20221310104_qris_to_bytes(st.session_state.qris_image)
            st.download_button(
                label="📥 Download QRIS",
                data=qris_bytes,
                file_name="digital_signature_qris.png",
                mime="image/png",
                key="download_qris_btn",
                type="primary"
            )
            
            st.markdown("""
            <div class="info-box">
                💡 <strong>Tips:</strong> Download QRIS ini dan kirim ke penerima untuk verifikasi.
                QRIS berisi pesan asli, signature, dan public key.
            </div>
            """, unsafe_allow_html=True)


def f20221310104_receiver_page():
    """Halaman Penerima - Verifikasi tanda tangan digital"""
    
    st.markdown('<h1 class="main-header">✅ Penerima Pesan</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Verifikasi keaslian pesan dari QRIS digital signature</p>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        # Upload QRIS or input data
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">
                <span class="step-indicator">1</span>
                Input Data QRIS
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        input_method = st.radio(
            "Pilih metode input:",
            ["📝 Input Manual", "📷 Upload QRIS Image"],
            horizontal=True
        )
        
        qris_data = None
        
        if input_method == "📝 Input Manual":
            st.markdown("#### Pesan")
            message = st.text_area(
                "Pesan yang diterima:",
                placeholder="Masukkan pesan...",
                height=100,
                key="recv_message"
            )
            
            st.markdown("#### Digital Signature")
            signature = st.text_area(
                "Signature (Base64):",
                placeholder="Masukkan digital signature...",
                height=80,
                key="recv_signature"
            )
            
            st.markdown("#### Public Key")
            public_key_pem = st.text_area(
                "Public Key (PEM format):",
                placeholder="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
                height=150,
                key="recv_pubkey"
            )
            
            if message and signature and public_key_pem:
                qris_data = {
                    "message": message,
                    "signature": signature,
                    "public_key": public_key_pem
                }
        
        else:
            uploaded_file = st.file_uploader(
                "Upload QRIS Image",
                type=['png', 'jpg', 'jpeg'],
                key="qris_upload"
            )
            
            if uploaded_file:
                # Display uploaded image
                st.image(uploaded_file, caption="QRIS yang diupload", use_container_width=True)
                
                # For QR decoding, we need to use a different approach
                # Since pyzbar has installation issues on Windows, 
                # we'll use the base64 data directly
                st.markdown("""
                <div class="info-box">
                    📌 <strong>Note:</strong> Untuk demo, silakan gunakan input manual 
                    atau copy data dari QRIS yang di-generate.
                </div>
                """, unsafe_allow_html=True)
                
                # Input for encoded QR data
                encoded_data = st.text_area(
                    "Atau masukkan data QRIS (base64):",
                    placeholder="Paste encoded QRIS data here...",
                    height=100,
                    key="encoded_qr"
                )
                
                if encoded_data:
                    qris_data = f20221310104_decode_qris_data(encoded_data)
                    if qris_data:
                        st.success("✅ Data QRIS berhasil di-decode!")
                    else:
                        st.error("❌ Gagal decode data QRIS")
    
    with col2:
        # Verification
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">
                <span class="step-indicator">2</span>
                Hasil Verifikasi
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if qris_data:
            # Display extracted data
            with st.expander("📋 Data yang Diterima", expanded=True):
                st.markdown("**Pesan:**")
                st.info(qris_data.get("message", ""))
                
                st.markdown("**Signature:**")
                sig = qris_data.get("signature", "")
                st.code(sig[:50] + "..." if len(sig) > 50 else sig)
            
            if st.button("🔍 Verifikasi Signature", key="verify_btn"):
                with st.spinner("Memverifikasi signature..."):
                    try:
                        # Import public key
                        public_key = f20221310104_import_public_key(qris_data["public_key"])
                        
                        # Verify signature
                        is_valid = f20221310104_verify_signature(
                            qris_data["message"],
                            qris_data["signature"],
                            public_key
                        )
                        
                        if is_valid:
                            st.markdown("""
                            <div class="success-box">
                                ✅ SIGNATURE VALID!<br>
                                <small>Pesan asli dan belum dimodifikasi</small>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            st.balloons()
                            
                            # Show message details
                            st.markdown("### 📨 Isi Pesan Asli")
                            st.markdown(f"""
                            <div class="custom-card" style="background: rgba(17, 153, 142, 0.2); border-color: #11998e;">
                                <p style="color: white; font-size: 1.1rem; margin: 0;">
                                    {qris_data["message"]}
                                </p>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # Show hash comparison
                            message_hash = f20221310104_get_hash_hex(qris_data["message"])
                            st.markdown("### 🔐 Detail Kriptografi")
                            st.markdown(f"""
                            <div class="info-box">
                                <strong>SHA-256 Hash Pesan:</strong><br>
                                <code style="font-size: 0.75rem; word-break: break-all;">{message_hash}</code>
                            </div>
                            """, unsafe_allow_html=True)
                            
                        else:
                            st.markdown("""
                            <div class="error-box">
                                ❌ SIGNATURE TIDAK VALID!<br>
                                <small>Pesan mungkin telah dimodifikasi atau signature palsu</small>
                            </div>
                            """, unsafe_allow_html=True)
                            
                    except Exception as e:
                        st.error(f"Error saat verifikasi: {str(e)}")
        else:
            st.markdown("""
            <div class="info-box">
                👈 Silakan input data QRIS terlebih dahulu untuk memulai verifikasi.
            </div>
            """, unsafe_allow_html=True)


def f20221310104_about_page():
    """Halaman tentang aplikasi dan cara kerja"""
    
    st.markdown('<h1 class="main-header">📖 Tentang Aplikasi</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Digital Signature Verification System dengan RSA dan QRIS</p>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">🔐 Apa itu Digital Signature?</div>
        <p style="color: rgba(255,255,255,0.8);">
            Digital Signature adalah mekanisme kriptografi yang menjamin:
        </p>
        <ul style="color: rgba(255,255,255,0.8);">
            <li><strong>Integritas</strong> - Pesan tidak dimodifikasi</li>
            <li><strong>Autentikasi</strong> - Identitas pengirim terverifikasi</li>
            <li><strong>Non-repudiation</strong> - Pengirim tidak bisa menyangkal</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">🔑 Algoritma RSA</div>
            <p style="color: rgba(255,255,255,0.8);">
                RSA (Rivest–Shamir–Adleman) adalah algoritma kriptografi asimetris 
                yang menggunakan pasangan kunci:
            </p>
            <ul style="color: rgba(255,255,255,0.8);">
                <li><strong>Private Key</strong> - Untuk menandatangani (rahasia)</li>
                <li><strong>Public Key</strong> - Untuk verifikasi (publik)</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="custom-card">
            <div class="card-title">📊 SHA-256 Hashing</div>
            <p style="color: rgba(255,255,255,0.8);">
                SHA-256 menghasilkan hash 256-bit yang unik untuk setiap pesan.
                Digunakan untuk:
            </p>
            <ul style="color: rgba(255,255,255,0.8);">
                <li>Mengecilkan ukuran data yang ditandatangani</li>
                <li>Memastikan integritas pesan</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="custom-card">
        <div class="card-title">📱 Alur Kerja</div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    ```
    ┌─────────────────────────────────────────────────────────────────┐
    │                         PENGIRIM                                │
    ├─────────────────────────────────────────────────────────────────┤
    │  1. Generate Kunci RSA (Public + Private Key)                   │
    │  2. Tulis Pesan                                                 │
    │  3. Hash Pesan dengan SHA-256                                   │
    │  4. Enkripsi Hash dengan Private Key → Digital Signature        │
    │  5. Generate QRIS berisi (Pesan + Signature + Public Key)       │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                         PENERIMA                                │
    ├─────────────────────────────────────────────────────────────────┤
    │  1. Scan/Input QRIS                                             │
    │  2. Extract: Pesan, Signature, Public Key                       │
    │  3. Hash Pesan yang diterima dengan SHA-256                     │
    │  4. Dekripsi Signature dengan Public Key                        │
    │  5. Bandingkan hasil dekripsi dengan Hash pesan                 │
    │  6. Jika sama → VALID ✅ | Jika beda → INVALID ❌               │
    └─────────────────────────────────────────────────────────────────┘
    ```
    """)


def f20221310104_main():
    """Main function"""
    
    # Sidebar navigation
    with st.sidebar:
        st.markdown("""
        <div style="text-align: center; padding: 1rem 0;">
            <h2 style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
                       -webkit-background-clip: text;
                       -webkit-text-fill-color: transparent;
                       margin: 0;">
                🔐 DigiSign
            </h2>
            <p style="color: rgba(255,255,255,0.6); font-size: 0.85rem;">
                RSA Digital Signature & QRIS
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        page = st.radio(
            "📍 Navigasi",
            ["✍️ Pengirim", "✅ Penerima", "📖 Tentang"],
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        
        st.markdown("""
        <div style="padding: 1rem; background: rgba(255,255,255,0.05); border-radius: 12px;">
            <p style="color: rgba(255,255,255,0.6); font-size: 0.8rem; margin: 0;">
                <strong>Tech Stack:</strong><br>
                🐍 Python<br>
                🎨 Streamlit<br>
                🔐 PyCryptodome<br>
                📱 QRCode
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    # Route to pages
    if page == "✍️ Pengirim":
        f20221310104_sender_page()
    elif page == "✅ Penerima":
        f20221310104_receiver_page()
    else:
        f20221310104_about_page()


if __name__ == "__main__":
    f20221310104_main()
