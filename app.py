import streamlit as st
import os
import pandas as pd
import shutil
import hashlib
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
os.makedirs("quarantine_storage", exist_ok=True)

USER_FILE = "users.csv"
LOG_FILE = "audit_logs.csv"
MSG_FILE = "messages.csv"
INCIDENT_FILE = "incidents.csv"
INTEGRITY_FILE = "integrity_hashes.csv"

# Faylların ilkin yaradılması
if not os.path.exists(USER_FILE):
    # Varsayılan admin və bir işçi hesabı yaradırıq (şifrələr hash-lənmiş formada: admin123 və 123)
    admin_pass_hash = hashlib.sha256("admin123".encode()).hexdigest()
    user_pass_hash = hashlib.sha256("123".encode()).hexdigest()
    df_users_init = pd.DataFrame({
        "Username": ["admin", "user"],
        "PasswordHash": [admin_pass_hash, user_pass_hash],
        "Role": ["Admin (ISO 27001)", "İşçi (User)"]
    })
    df_users_init.to_csv(USER_FILE, index=False)

if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["Tarix", "İstifadəçi", "Əməliyyat", "Detal"]).to_csv(LOG_FILE, index=False)

if not os.path.exists(MSG_FILE):
    pd.DataFrame(columns=["Tarix", "Kimdən", "Məzmun"]).to_csv(MSG_FILE, index=False)

if not os.path.exists(INCIDENT_FILE):
    pd.DataFrame(columns=["Tarix", "İnsident Başlığı", "ISO 27001 Kateqoriya", "Status", "Cavabdeh Tədbir"]).to_csv(INCIDENT_FILE, index=False)

if not os.path.exists(INTEGRITY_FILE):
    pd.DataFrame(columns=["Fayl Adı", "İstifadəçi", "SHA-256 Hash"]).to_csv(INTEGRITY_FILE, index=False)

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

def save_file_hash(filename, username, file_bytes):
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    df = pd.read_csv(INTEGRITY_FILE)
    df = df[df["Fayl Adı"] != filename]
    new_row = pd.DataFrame({"Fayl Adı": [filename], "İstifadəçi": [username], "SHA-256 Hash": [file_hash]})
    pd.concat([df, new_row], ignore_index=True).to_csv(INTEGRITY_FILE, index=False)
    return file_hash

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- GİRİŞ VƏ QEYDİYYAT (LOGIN / SIGN UP) -----------------
if not st.session_state.logged_in:
    st.title("🔐 Təhlükəsiz Bulud Platforması (IAM & Multi-User Authentication)")
    st.write("Sistemə daxil olun və ya yeni hesab yaradaraq bulud saxlancından istifadə edin.")
    
    auth_tab1, auth_tab2 = st.tabs(["🔑 Log In (Giriş)", "📝 Sign Up (Qeydiyyat)"])

    with auth_tab1:
        st.subheader("Hesabınıza Daxil Olun")
        input_user = st.text_input("İstifadəçi Adı:", key="login_user")
        input_pass = st.text_input("Şifrə:", type="password", key="login_pass")

        if st.button("Daxil Ol"):
            df_users = pd.read_csv(USER_FILE)
            pass_hash = hashlib.sha256(input_pass.encode()).hexdigest()
            
            user_row = df_users[(df_users["Username"] == input_user) & (df_users["PasswordHash"] == pass_hash)]
            
            if not user_row.empty:
                st.session_state.logged_in = True
                st.session_state.role = user_row.iloc[0]["Role"]
                st.session_state.username = input_user
                log_action(input_user, "Uğurlu Giriş", f"{input_user} sistemə daxil oldu")
                st.rerun()
            else:
                log_action(input_user if input_user else "Naməlum", "Kritik Təhlükə: Səlahiyyətsiz Giriş Cəhdi", f"Yanlış istifadəçi adı və ya şifrə")
                add_incident(f"Səlahiyyətsiz Giriş Cəhdi ({input_user})", "Səlahiyyət Pozuntusu", "Açıq", "IP izləndi və loglandı")
                st.error("❌ Yanlış istifadəçi adı və ya şifrə!")

    with auth_tab2:
        st.subheader("Yeni İstifadəçi Hesabı Yarat")
        new_user = st.text_input("Yeni İstifadəçi Adı Seçin:", key="signup_user")
        new_pass = st.text_input("Yeni Şifrə Seçin:", type="password", key="signup_pass")
        new_pass_confirm = st.text_input("Şifrəni Təsdiqləyin:", type="password", key="signup_pass_conf")

        if st.button("Qeydiyyatdan Keç"):
            df_users = pd.read_csv(USER_FILE)
            if not new_user.strip() or not new_pass.strip():
                st.error("Bütün xanaları doldurun!")
            elif new_user in df_users["Username"].values:
                st.error("Bu istifadəçi adı artıq mövcuddur! Başqa ad seçin.")
            elif new_pass != new_pass_confirm:
                st.error("Şifrələr bir-biri ilə uyğun gəlmir!")
            else:
                new_pass_hash = hashlib.sha256(new_pass.encode()).hexdigest()
                new_row = pd.DataFrame({
                    "Username": [new_user],
                    "PasswordHash": [new_pass_hash],
                    "Role": ["İşçi (User)"]
                })
                df_users = pd.concat([df_users, new_row], ignore_index=True)
                df_users.to_csv(USER_FILE, index=False)
                log_action(new_user, "Yeni Qeydiyyat", "İstifadəçi uğurla qeydiyyatdan keçdi")
                st.success("🎉 Qeydiyyat uğurla tamamlandı! İndi 'Log In' səhifəsindən daxil ola bilərsiniz.")

# ----------------- ƏSAS SİSTEM (GİRİŞ EDİLDİKDƏN SONRA) -----------------
else:
    st.sidebar.title(f"🛡️ Xoş gəldin, {st.session_state.username}")
    st.sidebar.write(f"Rol: **{st.session_state.role}**")
    
    if st.sidebar.button("🚪 Sistemdən Çıxış (Logout)"):
        log_action(st.session_state.username, "Sistemdən Çıxış", "Sistemdən çıxıldı")
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = ""
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.info("Multi-User Cloud Security & ISO 27001 Platforması.")

    # 1. İŞÇİ PANELİ (User)
    if st.session_state.role == "İşçi (User)":
        st.title(f"📁 Bulud Saxlanc Mərkəzi — İstifadəçi: {st.session_state.username}")
        st.write("Burada yalnız sizin öz fayllarınız saxlanılır. Fayllarınız AES ilə şifrələnir və SHA-256 ilə qorunur.")

        uploaded_file = st.file_uploader("Buluda yükləmək üçün fayl seçin", type=["txt", "pdf", "png", "jpg", "csv", "exe", "bat"])

        if uploaded_file is not None:
            file_name = uploaded_file.name.lower()
            if any(file_name.endswith(ext) for ext in [".exe", ".bat", ".sh", ".cmd"]):
                st.error(f"🚨 Təhlükə Aşkarlandı! '{uploaded_file.name}' zərərli proqram (Malware) imzası daşıyır.")
                if st.button("Faylı Karantinə Al"):
                    file_bytes = uploaded_file.read()
                    with open(os.path.join("quarantine_storage", f"{st.session_state.username}_{uploaded_file.name}"), "wb") as f:
                        f.write(file_bytes)
                    log_action(st.session_state.username, "Malware Aşkarlandı", f"{uploaded_file.name} karantinə atıldı")
                    add_incident(f"Malware Yüklənməsi ({st.session_state.username})", "Bütövlük Pozuntusu", "Araşdırılır", "Karantinə alındı")
                    st.warning("Fayl karantin qovluğuna köçürüldü!")
            else:
                if st.button("Şifrələ, Hash-lə və Buluda Göndər"):
                    file_bytes = uploaded_file.read()
                    encrypted_data = cipher_suite.encrypt(file_bytes)
                    
                    # Fayl adına istifadəçi adı əlavə edirik ki, hər kəsin faylı ayrı olsun
                    stored_filename = f"{st.session_state.username}_{uploaded_file.name}.enc"
                    file_path = os.path.join("encrypted_storage", stored_filename)
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    file_hash = save_file_hash(uploaded_file.name, st.session_state.username, file_bytes)
                    
                    log_action(st.session_state.username, "Fayl Yüklənməsi", f"{uploaded_file.name} şifrələndi")
                    st.success(f"Uğurludur! Faylınız şifrələnərək buluda yükləndi.")
                    st.code(f"SHA-256 Bütövlük İzi: {file_hash}")

        st.markdown("### Sizin Buluddakı Fayllarınız:")
        all_files = os.listdir("encrypted_storage")
        # Yalnız cari istifadəçinin fayllarını göstəririk
        user_files = [f for f in all_files if f.startswith(f"{st.session_state.username}_")]

        if user_files:
            selected_file = st.selectbox("Fayl seçin:", user_files)
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Deşifrə et və Endir"):
                    file_path = os.path.join("encrypted_storage", selected_file)
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    try:
                        decrypted_data = cipher_suite.decrypt(encrypted_data)
                        original_name = selected_file.replace(f"{st.session_state.username}_", "").replace(".enc", "")
                        st.download_button(label="Orijinal Faylı Endir", data=decrypted_data, file_name=original_name)
                        log_action(st.session_state.username, "Fayl Endirilməsi", f"{original_name} deşifrə edildi")
                    except Exception as e:
                        st.error("Deşifrələmə xətası!")
            with col_b:
                if st.button("Faylı Sil (Arxivə At)"):
                    src = os.path.join("encrypted_storage", selected_file)
                    dst = os.path.join("backup_storage", selected_file)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Fayl Silinməsi", f"{selected_file} arxivə daşındı")
                    st.warning("Fayl silindi və ehtiyat nüsxəyə köçürüldü!")
                    st.rerun()
        else:
            st.info("Bulud saxlancınızda hələ ki fayl yoxdur.")

        st.markdown("---")
        st.subheader("💬 Adminə Müraciət və Dəstək")
        msg_text = st.text_area("Adminə mesajınız:")
        if st.button("Mesajı Göndər"):
            if msg_text.strip():
                send_message(st.session_state.username, msg_text)
                st.success("Mesajınız adminə göndərildi!")

    # 2. ADMIN PANELİ (Admin)
    else:
        st.title("⚙️ İTİS & Multi-User İdarəetmə Paneli (Admin)")
        st.write("Bütün istifadəçilərin hesablama mühiti, təhlükəsizlik logları və insidentlər.")

        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "📊 CIA & Risk Matrisi", 
            "👥 Qeydiyyatda Olan İstifadəçilər", 
            "🔐 Fayl Bütövlüyü", 
            "🚨 İnsidentlər", 
            "🦠 Malware Karantini", 
            "📜 Audit Logları", 
            "🔄 Bərpa (Recovery)", 
            "💬 İstifadəçi Mesajları"
        ])

        with tab1:
            st.subheader("CIA Triad və ISO 27001 Nəzarət Matrisi")
            cia_data = {
                "CIA Komponenti": ["Konfidensiallıq", "Bütövlük", "Əlçatanlıq"],
                "Tətbiq Olunan Texnologiya": ["AES Şifrələmə & SHA-256 Şifrələnmiş Parollar", "SHA-256 File Integrity Hash", "Cloud Backup & Disaster Recovery"],
                "Status": ["Aktiv Qorunur", "Aktiv Yoxlanılır", "Aktiv Qorunur"]
            }
            st.dataframe(pd.DataFrame(cia_data), use_container_width=True)

        with tab2:
            st.subheader("👥 Sistemdə Qeydiyyatda Olan İstifadəçilər")
            st.write("Hər bir istifadəçi fərqli hesabla daxil olur. Parollar heç vaxt açıq şəkildə saxlanılmır (Password Hashing).")
            if os.path.exists(USER_FILE):
                df_u = pd.read_csv(USER_FILE)[["Username", "Role"]] # Şifrə hash-lərini təhlükəsizlik üçün adminə də göstərmirik!
                st.dataframe(df_u, use_container_width=True)

        with tab3:
            st.subheader("🔐 Fayl Bütövlüyü (SHA-256 Hashes)")
            if os.path.exists(INTEGRITY_FILE):
                st.dataframe(pd.read_csv(INTEGRITY_FILE), use_container_width=True)

        with tab4:
            st.subheader("🚨 Təhlükəsizlik İnsidentləri")
            if os.path.exists(INCIDENT_FILE):
                st.dataframe(pd.read_csv(INCIDENT_FILE), use_container_width=True)

        with tab5:
            st.subheader("🦠 Malware Karantini")
            q_files = os.listdir("quarantine_storage")
            if q_files:
                q_sel = st.selectbox("Karantin faylı:", q_files)
                if st.button("Faylı Təmizlə və Sil"):
                    os.remove(os.path.join("quarantine_storage", q_sel))
                    st.success("Zərərli fayl silindi!")
                    st.rerun()
            else:
                st.info("Karantin qovluğu boşdur.")

        with tab6:
            st.subheader("📜 Audit Logları")
            if os.path.exists(LOG_FILE):
                st.dataframe(pd.read_csv(LOG_FILE), use_container_width=True)

        with tab7:
            st.subheader("🔄 Bərpa (Disaster Recovery)")
            b_files = os.listdir("backup_storage")
            if b_files:
                b_sel = st.selectbox("Bərpa ediləcək:", b_files, key="b_f")
                if st.button("Faylı Bərpa Et"):
                    shutil.move(os.path.join("backup_storage", b_sel), os.path.join("encrypted_storage", b_sel))
                    st.success("Fayl bərpa olundu!")
                    st.rerun()
            else:
                st.info("Backup boşdur.")

        with tab8:
            st.subheader("💬 İstifadəçi Mesajları")
            if os.path.exists(MSG_FILE):
                st.dataframe(pd.read_csv(MSG_FILE), use_container_width=True)
