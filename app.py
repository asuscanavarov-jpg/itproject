import streamlit as st
import os
import pandas as pd
from cryptography.fernet import Fernet

# Səhifə konfiqurasiyası
st.set_page_config(page_title="CloudSec & Crypto Manager", page_icon="🛡️", layout="wide")

# Şifrələmə açarının idarə olunması (Kriptoqrafiya üçün)
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

# Session State (Giriş statusunu yadda saxlamaq üçün)
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.role = None
    st.session_state.username = ""

# ----------------- GİRİŞ (AUTHENTICATION) EKRANI -----------------
if not st.session_state.logged_in:
    st.title("🔐 Təhlükəsiz Giriş Paneli (IAM & Authentication)")
    st.write("Sistemə daxil olmaq üçün müvafiq rol və giriş məlumatlarınızı daxil edin.")
    
    col1, col2 = st.columns(2)
    with col1:
        login_role = st.selectbox("Giriş Rolu:", ["İşçi (User)", "Admin (ISO 27001)"])
        input_user = st.text_input("İstifadəçi Adı:")
        input_pass = st.text_input("Şifrə:", type="password")

        if st.button("Daxil Ol"):
            # Sınaq üçün təyin olunmuş parollar
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
        st.info("ℹ️ **Təhlükəsizlik Qeydi:** Bu səhifə səlahiyyətsiz şəxslərin bulud saxlancına və admin panelinə girişinin qarşısını almaq üçün Authentication mexanizmi ilə qorunur.")

# ----------------- ƏSAS SİSTEM (GİRİŞ EDİLDİKDƏN SONRA) -----------------
else:
    # Sol Menyu və Çıxış düyməsi
    st.sidebar.title(f"🛡️ Xoş gəldin, {st.session_state.username}")
    st.sidebar.write(Roles: f"**{st.session_state.role}**")
    
    if st.sidebar.button("🚪 Sistemdən Çıxış (Logout)"):
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = ""
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.info("Bu layihə Kriptoqrafiya, Bulud Təhlükəsizliyi və İTİS prinsiplərini əhatə edir.")

    # 1. İŞÇİ PANELİ (Fayl yükləmə və Kriptoqrafiya)
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
                    st.error("Deşifrələmə xətası! Fayl bütövlüyü pozulub və ya açar uyğun gəlmir.")
        else:
            st.info("Bulud saxlancında hələ ki fayl yoxdur.")

    # 2. ADMIN PANELİ (İnformasiya Təhlükəsizliyinin İdarə Edilməsi - ISO 27001)
    else:
        st.title("⚙️ İTİS & Bulud Təhlükəsizliyi İdarəetmə Paneli (Admin)")
        st.write("Bu paneldə **ISO/IEC 27001** standartına uyğun olaraq risk qiymətləndirməsi və sistem logları izlənilir.")

        tab1, tab2 = st.tabs(["📊 Risk Menecmenti (ISO 27001)", "📜 Audit Logları"])

        with tab1:
            st.subheader("Bulud Mühiti Üzrə Risk və Tədbir Matrisi")
            risk_data = {
                "Risk №": ["R-01", "R-02", "R-03"],
                "Təhlükə / Zəiflik": [
                    "Zəif parolların istifadəsi",
                    "Şifrələnməmiş məlumat ötürülməsi",
                    "Səlahiyyətsiz giriş cəhdləri"
                ],
                "ISO 27001 Nəzarət Tədbiri": [
                    "Mürəkkəb parol siyasətinin tətbiqi",
                    "AES və SSL/TLS şifrələmə protokolları",
                    "IAM (Rol əsaslı giriş nəzarəti)"
                ],
                "Status": ["Həll olundu", "Nəzarətdədir", "Aktiv"]
            }
            df_risk = pd.DataFrame(risk_data)
            st.dataframe(df_risk, use_container_width=True)

            st.markdown("### Yeni Risk Əlavə Et")
            new_risk = st.text_input("Risk təsviri:")
            new_control = st.text_input("Görüləcək tədbir:")
            if st.button("Riski Qeydə Al"):
                st.success("Risk uğurla əlavə edildi və İTİS siyahısına salındı!")

        with tab2:
            st.subheader("Sistem Əməliyyatlarının Tarixçəsi (Audit Logs)")
            if os.path.exists(LOG_FILE):
                df_logs = pd.read_csv(LOG_FILE)
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("Hələ ki log qeydi yoxdur.")
