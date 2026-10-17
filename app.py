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

# Qovluqların yaradılması (Əsas saxlanc və Ehtiyat/Bərpa saxlancı)
os.makedirs("encrypted_storage", exist_ok=True)
os.makedirs("backup_storage", exist_ok=True)
LOG_FILE = "audit_logs.csv"

if not os.path.exists(LOG_FILE):
    df_init = pd.DataFrame(columns=["Tarix", "İstifadəçi", "Əməliyyat", "Detal"])
    df_init.to_csv(LOG_FILE, index=False)

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

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- GİRİŞ EKRANI -----------------
if not st.session_state.logged_in:
    st.title("🔐 Təhlükəsiz Giriş Paneli (IAM & Authentication)")
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
                st.rerun()
            elif login_role == "Admin (ISO 27001)" and input_user == "admin" and input_pass == "admin123":
                st.session_state.logged_in = True
                st.session_state.role = "Admin (ISO 27001)"
                st.session_state.username = input_user
                st.rerun()
            else:
                st.error("❌ Yanlış istifadəçi adı və ya şifrə!")
                st.info("💡 Test üçün:\n- İşçi: user / 123\n- Admin: admin / admin123")

    with col2:
        st.info("ℹ️ **Təhlükəsizlik Qeydi:** Bu səhifə səlahiyyətsiz şəxslərin bulud saxlancına girişinin qarşısını alır.")

# ----------------- ƏSAS SİSTEM -----------------
else:
    st.sidebar.title(f"🛡️ Xoş gəldin, {st.session_state.username}")
    st.sidebar.write(f"Rol: **{st.session_state.role}**")
    
    if st.sidebar.button("🚪 Sistemdən Çıxış (Logout)"):
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
                    st.warning(f"'{selected_file}' buluddan silindi və ehtiyat nüsxəyə (Backup) köçürüldü!")
                    st.rerun()
        else:
            st.info("Bulud saxlancında hələ ki fayl yoxdur.")

    # 2. ADMIN PANELİ (ISO 27001 & Disaster Recovery)
    else:
        st.title("⚙️ İTİS & Bulud Təhlükəsizliyi İdarəetmə Paneli (Admin)")
        st.write("Bu paneldə **ISO/IEC 27001** standartına uyğun risklər, loglar və bulud bərpaetmə mexanizmi idarə olunur.")

        tab1, tab2, tab3 = st.tabs(["📊 Risk Menecmenti", "📜 Audit Logları", "🔄 Bulud Bərpa (Disaster Recovery)"])

        with tab1:
            st.subheader("Bulud Mühiti Üzrə Risk və Tədbir Matrisi")
            risk_data = {
                "Risk №": ["R-01", "R-02", "R-03", "R-04"],
                "Təhlükə / Zəiflik": [
                    "Zəif parolların istifadəsi",
                    "Şifrələnməmiş məlumat ötürülməsi",
                    "Səlahiyyətsiz giriş cəhdləri",
                    "Məlumatların səhvən silinməsi (Data Loss)"
                ],
                "ISO 27001 Nəzarət Tədbiri": [
                    "Mürəkkəb parol siyasətinin tətbiqi",
                    "AES şifrələmə protokolları",
                    "IAM (Rol əsaslı giriş nəzarəti)",
                    "Avtomatik Backup və Disaster Recovery"
                ],
                "Status": ["Həll olundu", "Nəzarətdədir", "Aktiv", "Qorunur"]
            }
            df_risk = pd.DataFrame(risk_data)
            st.dataframe(df_risk, use_container_width=True)

        with tab2:
            st.subheader("Sistem Əməliyyatlarının Tarixçəsi (Audit Logs)")
            if os.path.exists(LOG_FILE):
                df_logs = pd.read_csv(LOG_FILE)
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("Hələ ki log qeydi yoxdur.")

        with tab3:
            st.subheader("🔄 Bulud Ehtiyat Nüsxəsi və Məlumatların Bərpası (Backup & Restore)")
            st.write("Admin tərəfindən silinmiş və ya itirilmiş fayllar avtomatik olaraq **Cloud Backup** qovluğunda saxlanılır. Onları istənilən vaxt bərpa edə bilərsiniz.")
            
            backup_files = os.listdir("backup_storage")
            if backup_files:
                restore_file = st.selectbox("Bərpa ediləcək faylı seçin:", backup_files)
                if st.button("Faylı Buluda Bərpa Et (Restore)"):
                    src = os.path.join("backup_storage", restore_file)
                    dst = os.path.join("encrypted_storage", restore_file)
                    shutil.move(src, dst)
                    log_action(st.session_state.username, "Fayl Bərpası", f"{restore_file} backup-dan bərpa edildi")
                    st.success(f"Uğurludur! {restore_file} faylı uğurla bulud saxlancına bərpa olundu.")
                    st.rerun()
            else:
                st.info("Ehtiyat nüsxədə (Backup) silinmiş fayl yoxdur.")
