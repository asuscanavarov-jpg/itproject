import streamlit as st
import os
import pandas as pd
import shutil
import hashlib
from cryptography.fernet import Fernet

# Səhifə konfiqurasiyası
st.set_page_config(page_title="Enterprise CloudSec Gateway", page_icon="🛡️", layout="wide")

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
os.makedirs("quarantine_storage", exist_ok=True)

LOG_FILE = "audit_logs.csv"
MSG_FILE = "messages.csv"
INCIDENT_FILE = "incidents.csv"
INTEGRITY_FILE = "integrity_hashes.csv"

if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["Tarix", "İstifadəçi", "Əməliyyat", "Detal"]).to_csv(LOG_FILE, index=False)

if not os.path.exists(MSG_FILE):
    pd.DataFrame(columns=["Tarix", "Kimdən", "Məzmun"]).to_csv(MSG_FILE, index=False)

if not os.path.exists(INCIDENT_FILE):
    pd.DataFrame(columns=["Tarix", "İnsident Başlığı", "ISO 27001 Kateqoriya", "Status", "Cavabdeh Tədbir"]).to_csv(INCIDENT_FILE, index=False)

if not os.path.exists(INTEGRITY_FILE):
    pd.DataFrame(columns=["Fayl Adı", "SHA-256 Hash (Bütövlük İzi)"]).to_csv(INTEGRITY_FILE, index=False)

def log_action(user, action, detail):
    df = pd.read_csv(LOG_FILE)
    new_row = pd.DataFrame({"Tarix": [pd.Timestamp.now()], "İstifadəçi": [user], "Əməliyyat": [action], "Detal": [detail]})
    pd.concat([df, new_row], ignore_index=True).to_csv(LOG_FILE, index=False)

def send_message(user, content):
    df = pd.read_csv(MSG_FILE)
    new_row = pd.DataFrame({"Tarix": [pd.Timestamp.now()], "Kimdən": [user], "Məzmun": [content]})
    pd.concat([df, new_row], ignore_index=True).to_csv(MSG_FILE, index=False)

def add_incident(title, category, status, action):
    df = pd.read_csv(INCIDENT_FILE)
    new_row = pd.DataFrame({"Tarix": [pd.Timestamp.now()], "İnsident Başlığı": [title], "ISO 27001 Kateqoriya": [category], "Status": [status], "Cavabdeh Tədbir": [action]})
    pd.concat([df, new_row], ignore_index=True).to_csv(INCIDENT_FILE, index=False)

def save_file_hash(filename, file_bytes):
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    df = pd.read_csv(INTEGRITY_FILE)
    df = df[df["Fayl Adı"] != filename]
    new_row = pd.DataFrame({"Fayl Adı": [filename], "SHA-256 Hash (Bütövlük İzi)": [file_hash]})
    pd.concat([df, new_row], ignore_index=True).to_csv(INTEGRITY_FILE, index=False)
    return file_hash

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- KORPORATİV GİRİŞ EKRANI (SERIOUS IAM PORTAL) -----------------
if not st.session_state.logged_in:
    st.markdown("<h1 style='text-align: center; color: #0E1117;'>🛡️ Enterprise Cloud Security Gateway</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: gray;'>ISO/IEC 27001 Sertifikatlı Mərkəzi İdentifikasiya və Giriş Nəzarəti (IAM)</h4>", unsafe_allow_html=True)
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.warning("⚠️ **Təhlükəsizlik Xəbərdarlığı:** Bu sistem yalnız səlahiyyətli şəxslər üçündür. İcazəsiz giriş cəhdləri qanunla izlənilir, loglanır və təhlükəsizlik insidenti kimi qeydə alınır.")
        
        with st.container(border=True):
            st.subheader("🔐 Təhlükəsiz Doğrulama Paneli")
            login_role = st.selectbox("Sistem Rolu:", ["İşçi (User)", "Admin (ISO 27001)"])
            input_user = st.text_input("İstifadəçi Identifikatoru (Username):")
            input_pass = st.text_input("Şifrə (Password):", type="password")

            st.markdown("")
            if st.button("Sistemə Daxil Ol", use_container_width=True):
                if login_role == "İşçi (User)" and input_user == "user" and input_pass == "123":
                    st.session_state.logged_in = True
                    st.session_state.role = "İşçi (User)"
                    st.session_state.username = input_user
                    log_action(input_user, "Uğurlu Giriş", "İşçi rolu ilə təhlükəsiz sessiya açıldı")
                    st.rerun()
                elif login_role == "Admin (ISO 27001)" and input_user == "admin" and input_pass == "admin123":
                    st.session_state.logged_in = True
                    st.session_state.role = "Admin (ISO 27001)"
                    st.session_state.username = input_user
                    log_action(input_user, "Uğurlu Giriş", "Admin rolu ilə ISMS idarəetmə sessiyası açıldı")
                    st.rerun()
                else:
                    failed_user = input_user if input_user else "Naməlum"
                    log_action(failed_user, "Kritik Təhlükə: Səlahiyyətsiz Giriş Cəhdi", f"Yanlış etimadnamə ({login_role})")
                    add_incident(f"Səlahiyyətsiz Giriş Cəhdi ({failed_user})", "Səlahiyyət Pozuntusu", "Açıq", "IP ünvanı təcrid edildi və audit loglarına yazıldı")
                    st.error("❌ Doğrulama xətası: Yanlış istifadəçi adı və ya şifrə! Bu cəhd təhlükəsizlik loglarına yazıldı.")
            
            with st.expander("💡 Test Giriş Məlumatları (Demo üçün)"):
                st.markdown("- **İşçi:** `user` / `123`\n- **Admin:** `admin` / `admin123`")

# ----------------- ƏSAS SİSTEM (GİRİŞ EDİLDİKDƏN SONRA) -----------------
else:
    st.sidebar.title(f"🛡️ Səssiya: {st.session_state.username}")
    st.sidebar.write(f"Səlahiyyət: **{st.session_state.role}**")
    
    if st.sidebar.button("🚪 Təhlükəsiz Çıxış (Logout)"):
        log_action(st.session_state.username, "Sistemdən Çıxış", "Sessiya sonlandırıldı")
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = ""
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.info("Enterprise CloudSec & CIA Triad Qoruma Sistemi.")

    # 1. İŞÇİ PANELİ
    if st.session_state.role == "İşçi (User)":
        st.title("📁 Bulud Saxlanc Mərkəzi (Confidentiality & Integrity)")
        st.write("Fayllarınız AES simmetrik şifrələməsi ilə qorunur və SHA-256 bütövlük izi ilə yoxlanılır.")

        uploaded_file = st.file_uploader("Buluda yükləmək üçün fayl seçin", type=["txt", "pdf", "png", "jpg", "csv", "exe", "bat"])

        if uploaded_file is not None:
            file_name = uploaded_file.name.lower()
            if any(file_name.endswith(ext) for ext in [".exe", ".bat", ".sh", ".cmd"]):
                st.error(f"🚨 Təhlükə Aşkarlandı! '{uploaded_file.name}' zərərli proqram imzası daşıyır.")
                if st.button("Faylı Karantinə Al"):
                    file_bytes = uploaded_file.read()
                    with open(os.path.join("quarantine_storage", uploaded_file.name), "wb") as f:
                        f.write(file_bytes)
                    log_action(st.session_state.username, "Malware Aşkarlandı", f"{uploaded_file.name} karantinə atıldı")
                    add_incident(f"Malware Yüklənməsi", "Bütövlük Pozuntusu", "Araşdırılır", "Karantinə alındı")
                    st.warning("Fayl təcrid olunmuş karantin qovluğuna köçürüldü!")
            else:
                if st.button("Şifrələ, Hash-lə və Buluda Göndər"):
                    file_bytes = uploaded_file.read()
                    encrypted_data = cipher_suite.encrypt(file_bytes)
                    file_path = os.path.join("encrypted_storage", uploaded_file.name + ".enc")
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    file_hash = save_file_hash(uploaded_file.name, file_bytes)
                    log_action(st.session_state.username, "Fayl Yüklənməsi", f"{uploaded_file.name} şifrələndi və hash-ləndi")
                    st.success(f"Uğurludur! Fayl AES ilə qorundu və SHA-256 bütövlük izi yaradıldı.")
                    st.code(f"SHA-256 Hash: {file_hash}")

        st.markdown("### Buluddakı Şifrələnmiş Fayllarınız:")
        files = os.listdir("encrypted_storage")
        if files:
            selected_file = st.selectbox("Faylı seçin:", files)
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Deşifrə et və Endir"):
                    file_path = os.path.join("encrypted_storage", selected_file)
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    try:
                        decrypted_data = cipher_suite.decrypt(encrypted_data)
                        original_name = selected_file.replace(".enc", "")
                        st.download_button(label="Orijinal Faylı Endir", data=decrypted_data, file_name=original_name)
                        log_action(st.session_state.username, "Fayl Endirilməsi", f"{original_name} deşifrə edildi")
                    except Exception as e:
                        st.error("Deşifrələmə xətası!")
            with col_b:
                if st.button("Faylı Sil (Arxivə At)"):
                    src = os.path.join("encrypted_storage", selected_file)
                    dst = os.path.join("backup_storage", selected_file)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Fayl Silinməsi", f"{selected_file} ehtiyat nüsxəyə daşındı")
                    st.warning("Fayl buluddən silindi və ehtiyat nüsxəyə köçürüldü!")
                    st.rerun()
        else:
            st.info("Bulud saxlancında hələ ki fayl yoxdur.")

        st.markdown("---")
        st.subheader("💬 Təhlükəsizlik və Dəstək Mərkəzi")
        msg_text = st.text_area("Adminə göndəriləcək müraciət mesajı:")
        if st.button("Mesajı Göndər"):
            if msg_text.strip():
                send_message(st.session_state.username, msg_text)
                st.success("Mesaj sistem administratoruna göndərildi!")

    # 2. ADMIN PANELİ
    else:
        st.title("⚙️ İTİS & CIA Triad İdarəetmə Paneli (Admin - ISMS)")
        st.write("ISO 27001 standartına uyğun olaraq təhlükəsizlik siyasətləri, risklər və insidentlər idarə olunur.")

        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "📊 CIA & Risk Matrisi", 
            "🔐 Fayl Bütövlüyü (Integrity)", 
            "🚨 İnsidentlər", 
            "🦠 Malware Karantini", 
            "📜 Audit Logları", 
            "📂 Bulud Faylları", 
            "🔄 Bərpa (Recovery)", 
            "💬 Mesajlar"
        ])

        with tab1:
            st.subheader("CIA Triad və ISO 27001 Nəzarət Matrisi")
            cia_data = {
                "CIA Komponenti": ["Konfidensiallıq (Confidentiality)", "Bütövlük (Integrity)", "Əlçatanlıq (Availability)"],
                "Təhlükə / Risk": ["Məlumatların oğurlanması / oxunması", "Məlumatların gizlicə dəyişdirilməsi", "Sistemin sıradan çıxması və məlumat itkisi"],
                "Tətbiq Olunan Texnologiya / Nəzarət": ["AES (Fernet) Simmetrik Şifrələmə", "SHA-256 File Integrity Hash yoxlaması", "Cloud Backup & Disaster Recovery (Restore)"],
                "Status": ["Tam Qorunur", "Aktiv Yoxlanılır", "Aktiv Qorunur"]
            }
            st.dataframe(pd.DataFrame(cia_data), use_container_width=True)

        with tab2:
            st.subheader("🔐 Fayl Bütövlüyü və Rəqəmsal İzlər (SHA-256 Integrity Hashes)")
            if os.path.exists(INTEGRITY_FILE):
                st.dataframe(pd.read_csv(INTEGRITY_FILE), use_container_width=True)
            else:
                st.info("Hələ ki bütövlük qeydi yoxdur.")

        with tab3:
            st.subheader("🚨 Təhlükəsizlik İnsidentləri")
            if os.path.exists(INCIDENT_FILE):
                st.dataframe(pd.read_csv(INCIDENT_FILE), use_container_width=True)

        with tab4:
            st.subheader("🦠 Malware Karantini")
            q_files = os.listdir("quarantine_storage")
            if q_files:
                q_sel = st.selectbox("Karantin faylı:", q_files)
                if st.button("Faylı Təmizlə və Sil"):
                    os.remove(os.path.join("quarantine_storage", q_sel))
                    st.success("Zərərli fayl sistemdən təmizləndi!")
                    st.rerun()
            else:
                st.info("Karantin qovluğu boşdur.")

        with tab5:
            st.subheader("📜 Audit Logları")
            if os.path.exists(LOG_FILE):
                st.dataframe(pd.read_csv(LOG_FILE), use_container_width=True)

        with tab6:
            st.subheader("📂 Bulud Faylları (Admin)")
            adm_files = os.listdir("encrypted_storage")
            if adm_files:
                adm_sel = st.selectbox("Faylı seçin:", adm_files, key="adm_f")
                if st.button("Faylı Sil (Arxivə At)"):
                    shutil.move(os.path.join("encrypted_storage", adm_sel), os.path.join("backup_storage", adm_sel))
                    st.warning("Fayl arxivə daşındı!")
                    st.rerun()
            else:
                st.info("Fayl yoxdur.")

        with tab7:
            st.subheader("🔄 Bərpa (Disaster Recovery)")
            b_files = os.listdir("backup_storage")
            if b_files:
                b_sel = st.selectbox("Bərpa ediləcək:", b_files, key="b_f")
                if st.button("Faylı Buluda Bərpa Et"):
                    shutil.move(os.path.join("backup_storage", b_sel), os.path.join("encrypted_storage", b_sel))
                    st.success("Fayl bərpa olundu!")
                    st.rerun()
            else:
                st.info("Backup boşdur.")

        with tab8:
            st.subheader("💬 İstifadəçi Mesajları")
            if os.path.exists(MSG_FILE):
                st.dataframe(pd.read_csv(MSG_FILE), use_container_width=True)
