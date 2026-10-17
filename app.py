import streamlit as st
import os
import pandas as pd
import shutil
from cryptography.fernet import Fernet

# Səhifə konfiqurasiyası
st.set_page_config(page_title="CloudSec & Crypto Manager", page_icon="🛡️", layout="wide")

# Şifrələmə açarının idarə olunması
KEY_FILE = "secret.key"

def load_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

cipher_suite = Fernet(load_or_create_key())

# Qovluqların yaradılması
os.makedirs("encrypted_storage", exist_ok=True)
os.makedirs("backup_storage", exist_ok=True)

LOG_FILE = "audit_logs.csv"
MSG_FILE = "messages.csv"
INCIDENT_FILE = "incidents.csv"

if not os.path.exists(LOG_FILE):
    df_init = pd.DataFrame(columns=["Tarix", "İstifadəçi", "Əməliyyat", "Detal"])
    df_init.to_csv(LOG_FILE, index=False)

if not os.path.exists(MSG_FILE):
    df_msg_init = pd.DataFrame(columns=["Tarix", "Kimdən", "Məzmun"])
    df_msg_init.to_csv(MSG_FILE, index=False)

if not os.path.exists(INCIDENT_FILE):
    df_inc_init = pd.DataFrame(columns=["Tarix", "İnsident Başlığı", "ISO 27001 Kateqoriya", "Status", "Cavabdeh Tədbir"])
    df_inc_init.to_csv(INCIDENT_FILE, index=False)

def log_action(user, action, detail):
    df = pd.read_csv(LOG_FILE)
    new_row = pd.DataFrame({
        "Tarix": [pd.Timestamp.now()],
        "İstifadəçi": [user],
        "Əməliyyat": [action],
        "Detal": [detail]
    })
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(LOG_FILE, index=False)

def send_message(user, content):
    df = pd.read_csv(MSG_FILE)
    new_row = pd.DataFrame({
        "Tarix": [pd.Timestamp.now()],
        "Kimdən": [user],
        "Məzmun": [content]
    })
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(MSG_FILE, index=False)

def add_incident(title, category, status, action):
    df = pd.read_csv(INCIDENT_FILE)
    new_row = pd.DataFrame({
        "Tarix": [pd.Timestamp.now()],
        "İnsident Başlığı": [title],
        "ISO 27001 Kateqoriya": [category],
        "Status": [status],
        "Cavabdeh Tədbir": [action]
    })
    df = pd.concat([df, new_row], ignore_index=True)
    df.to_csv(INCIDENT_FILE, index=False)

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- GİRİŞ EKRANI -----------------
if not st.session_state.logged_in:
    st.title("🔐 Təhlükəsiz Giriş Paneli (IAM & Brute-Force Protection)")
    st.write("Sistemə daxil olmaq üçün müvafiq rol və giriş məlumatlarınızı daxil edin.")
    
    col1, col2 = st.columns(2)
    with col1:
        login_role = st.selectbox("Giriş Rolu:", ["İşçi (User)", "Admin (ISO 27001)"])
        input_user = st.text_input("İstifadəçi Adı:")
        input_pass = st.text_input("Şifrə:", type="password")

        if st.button("Daxil Ol"):
            if login_role == "İşçi (User)" and input_user == "user" and input_pass == "123":
                st.session_state.logged_in = True
                st.session_state.role = "İşçi (User)"
                st.session_state.username = input_user
                log_action(input_user, "Uğurlu Giriş", "İşçi rolu ilə sistemə daxil oldu")
                st.rerun()
            elif login_role == "Admin (ISO 27001)" and input_user == "admin" and input_pass == "admin123":
                st.session_state.logged_in = True
                st.session_state.role = "Admin (ISO 27001)"
                st.session_state.username = input_user
                log_action(input_user, "Uğurlu Giriş", "Admin rolu ilə sistemə daxil oldu")
                st.rerun()
            else:
                failed_user = input_user if input_user else "Naməlum"
                log_action(failed_user, "Kritik Təhlükə: Səlahiyyətsiz Giriş Cəhdi", f"Yanlış şifrə cəhdi ({login_role})")
                add_incident(f"Səlahiyyətsiz Giriş Cəhdi ({failed_user})", "Səlahiyyət Pozuntusu", "Açıq", "IP ünvanı izləndi və loglara yazıldı")
                st.error("❌ Yanlış istifadəçi adı və ya şifrə! Bu səlahiyyətsiz cəhd audit loglarına və ISMS insidentlərinə yazıldı.")
                st.info("💡 Test üçün:\n- İşçi: user / 123\n- Admin: admin / admin123")

    with col2:
        st.info("ℹ️ **Təhlükəsizlik Qeydi:** Səlahiyyətsiz girişlər və hücum cəhdləri avtomatik olaraq izlənilir.")

# ----------------- ƏSAS SİSTEM -----------------
else:
    st.sidebar.title(f"🛡️ Xoş gəldin, {st.session_state.username}")
    st.sidebar.write(f"Rol: **{st.session_state.role}**")
    
    if st.sidebar.button("🚪 Sistemdən Çıxış (Logout)"):
        log_action(st.session_state.username, "Sistemdən Çıxış", "İşçi/Admin sistemdən çıxdı")
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = ""
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.info("Bu layihə Kriptoqrafiya, Bulud Təhlükəsizliyi və İTİS prinsiplərini əhatə edir.")

    # 1. İŞÇİ PANELİ
    if st.session_state.role == "İşçi (User)":
        st.title("📁 Bulud Saxlanc Mərkəzi (Cloud Storage)")
        st.write("Buradan fayllarınızı buluda **AES** alqoritmi ilə şifrələnmiş şəkildə yükləyə bilərsiniz.")

        uploaded_file = st.file_uploader("Buluda yükləmək üçün fayl seçin", type=["txt", "pdf", "png", "jpg", "csv"])

        if uploaded_file is not None:
            if st.button("Şifrələ və Buluda Göndər"):
                file_bytes = uploaded_file.read()
                encrypted_data = cipher_suite.encrypt(file_bytes)
                
                file_path = os.path.join("encrypted_storage", uploaded_file.name + ".enc")
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)
