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
os.makedirs("quarantine_storage", exist_ok=True)

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

# ----------------- GİRİŞ EKRANI (Ssenari 3 İzləməsi) -----------------
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
                # Səlahiyyətsiz giriş cəhdi / Brute-force qeydi
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

    # 1. İŞÇİ PANELİ (Ssenari 2: Malware Skaneri)
    if st.session_state.role == "İşçi (User)":
        st.title("📁 Bulud Saxlanc Mərkəzi (Cloud Storage & Malware Scanner)")
        st.write("Buradan fayllarınızı buluda yükləyə bilərsiniz. Sistem faylları **AES** ilə şifrələyir və zərərli proqramlara qarşı yoxlayır.")

        uploaded_file = st.file_uploader("Buluda yükləmək üçün fayl seçin", type=["txt", "pdf", "png", "jpg", "csv", "exe", "bat", "sh"])

        if uploaded_file is not None:
            file_name = uploaded_file.name.lower()
            # Şübhəli / Malware uzantı yoxlaması
            risky_extensions = [".exe", ".bat", ".sh", ".cmd", ".js"]
            is_malicious = any(file_name.endswith(ext) for ext in risky_extensions)

            if is_malicious:
                st.error(f"🚨 Təhlükə Aşkarlandı! '{uploaded_file.name}' faylı zərərli proqram (Malware) imzası daşıyır!")
                if st.button("Faylı Karantinə Al (Quarantine)"):
                    file_bytes = uploaded_file.read()
                    q_path = os.path.join("quarantine_storage", uploaded_file.name)
                    with open(q_path, "wb") as f:
                        f.write(file_bytes)
                    log_action(st.session_state.username, "Kritik İnsident: Malware Aşkarlandı", f"{uploaded_file.name} karantinə alındı")
                    add_incident(f"Malware Fayl Yüklənməsi ({uploaded_file.name})", "Konfidensiallıq və Bütövlük", "Araşdırılır", "Fayl karantinə keçirildi və təcrid olundu")
                    st.warning("Fayl təcrid olunmuş 'Quarantine Storage' qovluğuna köçürüldü!")
            else:
                if st.button("Şifrələ və Buluda Göndər"):
                    file_bytes = uploaded_file.read()
                    encrypted_data = cipher_suite.encrypt(file_bytes)
                    
                    file_path = os.path.join("encrypted_storage", uploaded_file.name + ".enc")
                    with open(file_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    log_action(st.session_state.username, "Fayl Yüklənməsi", f"{uploaded_file.name} şifrələndi")
                    st.success(f"Uğurludur! '{uploaded_file.name}' faylı AES ilə şifrələnərək buludda qorundu.")

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
                        st.download_button(
                            label="Orijinal Faylı Endir",
                            data=decrypted_data,
                            file_name=original_name
                        )
                        log_action(st.session_state.username, "Fayl Endirilməsi", f"{original_name} deşifrə edildi")
                    except Exception as e:
                        st.error("Deşifrələmə xətası!")
            with col_b:
                if st.button("Faylı Sil (Arxivə At)"):
                    src = os.path.join("encrypted_storage", selected_file)
                    dst = os.path.join("backup_storage", selected_file)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Fayl Silinməsi", f"{selected_file} ehtiyat nüsxəyə daşındı")
                    st.warning(f"'{selected_file}' buluddan silindi və ehtiyat nüsxəyə köçürüldü!")
                    st.rerun()
        else:
            st.info("Bulud saxlancında hələ ki fayl yoxdur.")

        st.markdown("---")
        st.subheader("💬 Adminə Müraciət və Dəstək")
        msg_text = st.text_area("Adminə göndərmək üçün mesajınızı yazın:")
        if st.button("Mesajı Göndər"):
            if msg_text.strip():
                send_message(st.session_state.username, msg_text)
                st.success("Mesajınız adminə uğurla göndərildi!")
            else:
                st.error("Boş mesaj göndərmək olmaz!")

    # 2. ADMIN PANELİ
    else:
        st.title("⚙️ İTİS & Bulud Təhlükəsizliyi İdarəetmə Paneli (Admin - ISMS)")
        st.write("Bu paneldə **ISO/IEC 27001** standartına uyğun olaraq İTİS siyasətləri, insidentlər, malware karantini və audit logları idarə olunur.")

        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "📊 Risk Menecmenti", 
            "🚨 İnsidentlər & Səlahiyyət Pozuntuları", 
            "🦠 Malware Karantini", 
            "📜 Audit Logları", 
            "📂 Bulud Faylları (Admin)", 
            "🔄 Bulud Bərpa (Recovery)", 
            "💬 İstifadəçi Mesajları"
        ])

        with tab1:
            st.subheader("Bulud Mühiti Üzrə Risk və Tədbir Matrisi")
            risk_data = {
                "Risk №": ["R-01", "R-02", "R-03", "R-04", "R-05"],
                "Təhlükə / Zəiflik": [
                    "Zəif parolların istifadəsi",
                    "Şifrələnməmiş məlumat ötürülməsi",
                    "Səlahiyyətsiz giriş cəhdləri / Brute-Force",
                    "Zərərli proqram (Malware) yüklənməsi",
                    "Məlumatların səhvən silinməsi (Data Loss)"
                ],
                "ISO 27001 Nəzarət Tədbiri": [
                    "Mürəkkəb parol siyasətinin tətbiqi",
                    "AES şifrələmə protokolları",
                    "IAM və Avtomatik Səlahiyyətsiz Giriş Aşkarlanması",
                    "Real-time Malware Skaneri və Quarantine Storage",
                    "Avtomatik Backup və Disaster Recovery"
                ],
                "Status": ["Həll olundu", "Nəzarətdədir", "Aktiv Müdafiə", "Aktiv", "Qorunur"]
            }
            df_risk = pd.DataFrame(risk_data)
            st.dataframe(df_risk, use_container_width=True)

        with tab2:
            st.subheader("🚨 Təhlükəsizlik İnsidentləri və Səlahiyyət Pozuntuları (ISO 27001)")
            st.write("Sistem tərəfindən avtomatik aşkar edilən səlahiyyətsiz giriş cəhdləri və təhlükələr:")
            if os.path.exists(INCIDENT_FILE):
                df_inc = pd.read_csv(INCIDENT_FILE)
                if not df_inc.empty:
                    st.dataframe(df_inc, use_container_width=True)
                else:
                    st.info("Hələ ki qeydə alınmış insident yoxdur.")

        with tab3:
            st.subheader("🦠 Malware və Şübhəli Fayl Karantini (Quarantine Storage)")
            st.write("Sistem tərəfindən bloklanan və təcrid olunan zərərli fayllar:")
            quarantine_files = os.listdir("quarantine_storage")
            if quarantine_files:
                q_selected = st.selectbox("Karantindəki faylı seçin:", quarantine_files)
                col_q1, col_q2 = st.columns(2)
                with col_q1:
                    if st.button("Faylı Təmizlə və Sil (Purge)"):
                        os.remove(os.path.join("quarantine_storage", q_selected))
                        log_action(st.session_state.username, "Malware Silindi", f"{q_selected} karantindən silindi")
                        st.success("Zərərli fayl sistemdən təmizləndi!")
                        st.rerun()
                with col_q2:
                    if st.button("Təhlükəsiz hesab et və Buluda At"):
                        src = os.path.join("quarantine_storage", q_selected)
                        dst = os.path.join("encrypted_storage", q_selected + ".enc")
                        with open(src, "rb") as f:
                            enc_data = cipher_suite.encrypt(f.read())
                        with open(dst, "wb") as f:
                            f.write(enc_data)
                        os.remove(src)
                        log_action(st.session_state.username, "Karantindən Buraxıldı", f"{q_selected} buluda atıldı")
                        st.success("Fayl buluda köçürüldü!")
                        st.rerun()
            else:
                st.info("Karantin qovluğunda şübhəli fayl yoxdur. Sistem tam təhlükəsizdir!")

        with tab4:
            st.subheader("Sistem Əməliyyatlarının Tarixçəsi (Audit Logs)")
            if os.path.exists(LOG_FILE):
                df_logs = pd.read_csv(LOG_FILE)
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("Hələ ki log qeydi yoxdur.")

        with tab5:
            st.subheader("📂 Bulud Saxlancının İdarə Edilməsi (Admin Silmə Səlahiyyəti)")
            admin_files = os.listdir("encrypted_storage")
            if admin_files:
                adm_selected = st.selectbox("İdarə ediləcək faylı seçin:", admin_files, key="admin_file_sel")
                if st.button("Admin Səlahiyyəti ilə Faylı Sil (Arxivə At)"):
                    src = os.path.join("encrypted_storage", adm_selected)
                    dst = os.path.join("backup_storage", adm_selected)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Admin Fayl Silinməsi", f"{adm_selected} admin tərəfindən arxivə atıldı")
                    st.warning(f"Fayl admin tərəfindən buluddan silindi və bərpa qovluğuna daşındı!")
                    st.rerun()
            else:
                st.info("Bulud saxlancında fayl yoxdur.")

        with tab6:
            st.subheader("🔄 Bulud Ehtiyat Nüsxəsi və Məlumatların Bərpası (Backup & Restore)")
            backup_files = os.listdir("backup_storage")
            if backup_files:
                restore_file = st.selectbox("Bərpa ediləcək faylı seçin:", backup_files, key="restore_sel")
                if st.button("Faylı Buluda Bərpa Et (Restore)"):
                    src = os.path.join("backup_storage", restore_file)
                    dst = os.path.join("encrypted_storage", restore_file)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Fayl Bərpası", f"{restore_file} backup-dan bərpa edildi")
                    st.success(f"Uğurludur! '{restore_file}' faylı bulud saxlancına bərpa olundu.")
                    st.rerun()
            else:
                st.info("Ehtiyat nüsxədə (Backup) silinmiş fayl yoxdur.")

        with tab7:
            st.subheader("💬 İstifadəçilərdən Gələn Müraciətlər və Mesajlar")
            if os.path.exists(MSG_FILE):
                df_msgs = pd.read_csv(MSG_FILE)
                if not df_msgs.empty:
                    st.dataframe(df_msgs, use_container_width=True)
                else:
                    st.info("Hələ ki heç bir mesaj yoxdur.")
            else:
                st.info("Mesaj qovluğu boşdur.")
