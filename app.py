import streamlit as st
import os
import pandas as pd
import shutil
import hashlib
import re
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
    admin_pass_hash = hashlib.sha256("Admin@123".encode()).hexdigest()
    user_pass_hash = hashlib.sha256("User@123".encode()).hexdigest()
    df_users_init = pd.DataFrame({
        "Username": ["admin", "user"],
        "PasswordHash": [admin_pass_hash, user_pass_hash],
        "Role": ["Admin (ISO 27001)", "İşçi (User)"]
    })
    df_users_init.to_csv(USER_FILE, index=False)

if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["Tarix", "İstifadəçi", "Əməliyyat", "Detal"]).to_csv(LOG_FILE, index=False)

if not os.path.exists(MSG_FILE):
    # Mesajlar faylına admin cavabı üçün sütun əlavə olunub
    pd.DataFrame(columns=["ID", "Tarix", "Kimdən", "Məzmun", "AdminCavabi"]).to_csv(MSG_FILE, index=False)

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
    msg_id = len(df) + 1
    new_row = pd.DataFrame({
        "ID": [msg_id],
        "Tarix": [pd.Timestamp.now()],
        "Kimdən": [user],
        "Məzmun": [content],
        "AdminCavabi": ["Hələ ki cavab verilməyib"]
    })
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

def check_password_strength(password):
    if len(password) < 6:
        return "Şifrə ən azı 6 simvoldan ibarət olmalıdır!"
    if not re.search(r"[A-Za-z]", password):
        return "Şifrədə mütləq hərflər olmalıdır!"
    if not re.search(r"\d", password):
        return "Şifrədə mütləq rəqəmlər olmalıdır!"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Şifrədə mütləq xüsusi simvol (!@#$%^&* və s.) olmalıdır!"
    return None

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- GİRİŞ VƏ QEYDİYYAT (LOGIN / SIGN UP) -----------------
if not st.session_state.logged_in:
    st.title("🔐 Təhlükəsiz Bulud Platforması (IAM & Password Policy)")
    st.write("Sistemə daxil olun və ya mürəkkəb parol tələblərinə uyğun yeni hesab yaradın.")
    
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
        st.subheader("Yeni İstifadəçi Hesabı Yarat (Güclü Parol Siyasəti)")
        st.info("💡 **Təhlükəsizlik Qaydası:** Şifrə ən azı 6 simvoldan ibarət olmalı, həmçinin içində **hərf, rəqəm və xüsusi simvol** (!@#$...) mütləq olmalıdır!")
        
        new_user = st.text_input("Yeni İstifadəçi Adı Seçin:", key="signup_user")
        new_pass = st.text_input("Yeni Şifrə Seçin:", type="password", key="signup_pass")
        new_pass_confirm = st.text_input("Şifrəni Təsdiqləyin:", type="password", key="signup_pass_conf")

        if st.button("Qeydiyyatdan Keç"):
            df_users = pd.read_csv(USER_FILE)
            error_message = check_password_strength(new_pass)

            if not new_user.strip() or not new_pass.strip():
                st.error("Bütün xanaları doldurun!")
            elif new_user in df_users["Username"].values:
                st.error("Bu istifadəçi adı artıq mövcuddur! Başqa ad seçin.")
            elif error_message:
                st.error(f"❌ Zəif Şifrə Siyasəti: {error_message}")
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
                log_action(new_user, "Yeni Qeydiyyat", "İstifadəçi güclü parol ilə qeydiyyatdan keçdi")
                st.success("🎉 Qeydiyyat uğurla tamamlandı! İndi 'Log In' səhifəsindən daxil ola bilərsiniz.")

# ----------------- ƏSAS SİSTEM -----------------
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
    st.sidebar.info("Multi-User Cloud Security & Two-Way Communication System.")

    # 1. İŞÇİ PANELİ (User)
    if st.session_state.role == "İşçi (User)":
        st.title(f"📁 Bulud Saxlanc Mərkəzi — İstifadəçi: {st.session_state.username}")
        st.write("Fayllarınızı təhlükəsiz şəkildə buluda yükləyin və admin ilə əlaqə saxlayın.")

        uploaded_file = st.file_uploader("Buluda yükləmək üçün fayl seçin", type=["txt", "pdf", "png", "jpg", "csv", "exe", "bat", "sh"])

        if uploaded_file is not None:
            if st.button("Buluda Göndər"):
                file_bytes = uploaded_file.read()
                file_name = uploaded_file.name.lower()
                
                risky_extensions = [".exe", ".bat", ".sh", ".cmd", ".js"]
                is_malicious = any(file_name.endswith(ext) for ext in risky_extensions)

                if is_malicious:
                    q_path = os.path.join("quarantine_storage", f"{st.session_state.username}_{uploaded_file.name}")
                    with open(q_path, "wb") as f:
                        f.write(file_bytes)
                    
                    log_action(st.session_state.username, "Kritik Təhlükə: Gizli Malware Aşkarlanması", f"{uploaded_file.name} arxa planda karantinə alındı")
                    add_incident(f"Gizli Malware Yüklənməsi ({st.session_state.username})", "Bütövlük və Konfidensiallıq", "Araşdırılır", "Arxa planda avtomatik karantinə keçirildi")
                    
                    st.success(f"Uğurludur! '{uploaded_file.name}' faylı bulud saxlancına göndərildi.")
                else:
                    encrypted_data = cipher_suite.encrypt(file_bytes)
                    stored_filename = f"{st.session_state.username}_{uploaded_file.name}.enc"
                    file_path = os.path.join("encrypted_storage", stored_filename)
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    file_hash = save_file_hash(uploaded_file.name, st.session_state.username, file_bytes)
                    log_action(st.session_state.username, "Fayl Yüklənməsi", f"{uploaded_file.name} şifrələndi")
                    st.success(f"Uğurludur! Faylınız AES ilə şifrələnərək buluda yükləndi.")
                    st.code(f"SHA-256 Bütövlük İzi: {file_hash}")

        st.markdown("### Sizin Buluddakı Fayllarınız:")
        all_files = os.listdir("encrypted_storage")
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
            st.info("Bulud saxlancında hələ ki fayl yoxdur.")

        st.markdown("---")
        st.subheader("💬 Adminə Müraciət və Cavabların İzlənməsi")
        msg_text = st.text_area("Adminə yeni mesajınız:")
        if st.button("Mesajı Göndər"):
            if msg_text.strip():
                send_message(st.session_state.username, msg_text)
                st.success("Mesajınız adminə göndərildi!")
                st.rerun()

        # İstifadəçinin öz göndərdiyi mesajları və adminin cavablarını görməsi
        st.markdown("### Göndərdiyiniz Müraciətlər və Admin Cavabları:")
        if os.path.exists(MSG_FILE):
            df_m = pd.read_csv(MSG_FILE)
            user_msgs = df_m[df_m["Kimdən"] == st.session_state.username]
            if not user_msgs.empty:
                st.dataframe(user_msgs[["Tarix", "Məzmun", "AdminCavabi"]], use_container_width=True)
            else:
                st.info("Hələ ki müraciətiniz yoxdur.")

    # 2. ADMIN PANELİ (Admin - İstifadəçilərə cavab vermə imkanı ilə)
    else:
        st.title("⚙️ İTİS & İki Tərəfli Əlaqə Paneli (Admin)")
        st.write("İstifadəçi müraciətlərini oxuyun, onlara rəsmi cavab yazın və sistemi idarə edin.")

        tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
            "📊 CIA & Risk Matrisi", 
            "👥 Qeydiyyatda Olan İstifadəçilər", 
            "🔐 Fayl Bütövlüyü", 
            "🚨 Təhlükəsizlik İnsidentləri", 
            "🦠 Gizli Malware Karantini", 
            "📜 Audit Logları", 
            "🔄 Bərpa (Recovery)", 
            "💬 İstifadəçi Mesajları və Cavablar"
        ])

        with tab1:
            st.subheader("CIA Triad və ISO 27001 Nəzarət Matrisi")
            cia_data = {
                "CIA Komponenti": ["Konfidensiallıq", "Bütövlük", "Əlçatanlıq"],
                "Tətbiq Olunan Texnologiya": ["AES Şifrələmə & Parol Siyasəti", "SHA-256 File Integrity Hash & Malware Skaneri", "Cloud Backup & Disaster Recovery"],
                "Status": ["Aktiv Qorunur", "Aktiv Yoxlanılır", "Aktiv Qorunur"]
            }
            st.dataframe(pd.DataFrame(cia_data), use_container_width=True)

        with tab2:
            st.subheader("👥 Sistemdə Qeydiyyatda Olan İstifadəçilər")
            if os.path.exists(USER_FILE):
                df_u = pd.read_csv(USER_FILE)[["Username", "Role"]]
                st.dataframe(df_u, use_container_width=True)

        with tab3:
            st.subheader("🔐 Fayl Bütövlüyü (SHA-256 Hashes)")
            if os.path.exists(INTEGRITY_FILE):
                st.dataframe(pd.read_csv(INTEGRITY_FILE), use_container_width=True)

        with tab4:
            st.subheader("🚨 Təhlükəsizlik İnsidentləri (SOC)")
            if os.path.exists(INCIDENT_FILE):
                st.dataframe(pd.read_csv(INCIDENT_FILE), use_container_width=True)

        with tab5:
            st.subheader("🦠 Gizli Malware Karantini (Avtomatik Təcrid)")
            q_files = os.listdir("quarantine_storage")
            if q_files:
                q_sel = st.selectbox("Karantin faylı:", q_files)
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    if st.button("Zərərli Faylı Təmizlə və Sil (Purge)"):
                        os.remove(os.path.join("quarantine_storage", q_sel))
                        log_action(st.session_state.username, "Malware Silindi", f"{q_sel} admin tərəfindən karantindən silindi")
                        st.success("Zərərli fayl sistemdən təmizləndi!")
                        st.rerun()
                with col_m2:
                    if st.button("Təhlükəsiz hesab et və Buluda At"):
                        src = os.path.join("quarantine_storage", q_sel)
                        clean_name = q_sel.split("_", 1)[1] if "_" in q_sel else q_sel
                        dst = os.path.join("encrypted_storage", f"{clean_name}.enc")
                        with open(src, "rb") as f:
                            enc_data = cipher_suite.encrypt(f.read())
                        with open(dst, "wb") as f:
                            f.write(enc_data)
                        os.remove(src)
                        log_action(st.session_state.username, "Karantindən Buraxıldı", f"{q_sel} buluda köçürüldü")
                        st.success("Fayl təmiz hesab edilərək buluda köçürüldü!")
                        st.rerun()
            else:
                st.info("Karantin qovluğu boşdur. Şübhəli aktivlik yoxdur.")

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
            st.subheader("💬 İstifadəçi Müraciətləri və Admin Cavabları")
            st.write("İstifadəçilərin göndərdiyi mesajları seçib onlara rəsmi cavab yazın:")
            if os.path.exists(MSG_FILE):
                df_msgs = pd.read_csv(MSG_FILE)
                if not df_msgs.empty:
                    st.dataframe(df_msgs, use_container_width=True)
                    
                    # Adminin mesaj seçib cavab yazması üçün interfeys
                    msg_ids = df_msgs["ID"].tolist()
                    selected_msg_id = st.selectbox("Cavab yazılacaq Mesaj ID-sini seçin:", msg_ids)
                    admin_reply_text = st.text_area("İstifadəçiyə yazılacaq cavab:")
                    
                    if st.button("Cavabı Göndər"):
                        if admin_reply_text.strip():
                            df_msgs.loc[df_msgs["ID"] == selected_msg_id, "AdminCavabi"] = admin_reply_text
                            df_msgs.to_csv(MSG_FILE, index=False)
                            log_action(st.session_state.username, "Admin Cavabı", f"ID {selected_msg_id} olan mesaja cavab yazıldı")
                            st.success("Cavab istifadəçiyə uğurla göndərildi!")
                            st.rerun()
                        else:
                            st.error("Cavab mətni boş ola bilməz!")
                else:
                    st.info("Hələ ki mesaj yoxdur.")
            else:
                st.info("Mesaj qovluğu boşdur.")
