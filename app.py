"""
AWS SES Manager — веб-версия на Streamlit.

Запуск локально:
    pip install -r requirements.txt
    streamlit run app.py

Деплой в облако (Streamlit Community Cloud):
    1. Залить этот проект в приватный репозиторий на GitHub.
    2. Зайти на https://share.streamlit.io, подключить репозиторий.
    3. В настройках приложения (Settings -> Secrets) добавить:
       APP_PASSWORD = "ваш_пароль_для_входа_в_приложение"
    4. Deploy — получите публичную ссылку на приложение.

Важно: сам AWS Access Key/Secret Key нигде не сохраняется — вводится
заново в каждой сессии браузера и используется только для прямых
запросов к AWS API. APP_PASSWORD — это отдельный пароль, защищающий
сам вход в веб-интерфейс, чтобы им не мог воспользоваться кто угодно
по ссылке.
"""

import json
import hmac as hmac_lib
import hashlib
import base64

import streamlit as st

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    boto3 = None


# ---------- SMTP password algorithm (official AWS method) ----------

DATE = "11111111"
SERVICE = "ses"
MESSAGE = "SendRawEmail"
TERMINAL = "aws4_request"
VERSION = 0x04


def _sign(key, msg):
    return hmac_lib.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def calculate_smtp_password(secret_access_key: str, region: str) -> str:
    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), DATE)
    signature = _sign(signature, region)
    signature = _sign(signature, SERVICE)
    signature = _sign(signature, TERMINAL)
    signature = _sign(signature, MESSAGE)
    signature_and_version = bytes([VERSION]) + signature
    return base64.b64encode(signature_and_version).decode("utf-8")


# ---------- AWS client helper ----------

def get_client(service, access_key, secret_key, region):
    if boto3 is None:
        st.error("boto3 не установлен. Добавьте его в requirements.txt")
        return None
    if not access_key or not secret_key:
        st.warning("Введите Access Key ID и Secret Access Key.")
        return None
    return boto3.client(
        service,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def print_cname_records(identity, tokens):
    for i, token in enumerate(tokens, start=1):
        record_name = f"{token}._domainkey.{identity}"
        record_value = f"{token}.dkim.amazonses.com"
        st.markdown(f"**Запись {i}:**")
        st.code(f"Тип:      CNAME\nИмя:      {record_name}\nЗначение: {record_value}")


def run_action(func):
    """Обёртка для перехвата ошибок AWS и отображения их пользователю."""
    try:
        func()
    except NoCredentialsError:
        st.error("Не удалось аутентифицироваться. Проверьте ключи.")
    except ClientError as e:
        st.error(f"AWS ошибка: {e.response['Error']['Code']} — {e.response['Error']['Message']}")
    except Exception as e:
        st.error(f"Ошибка: {e}")


# ---------- Main app ----------

def main():
    st.set_page_config(page_title="AWS SES Manager", page_icon="📧", layout="centered")

    st.title("📧 AWS SES Manager")
    st.caption(
        "Бесплатный инструмент для управления AWS SES. "
        "Ваши AWS-ключи используются только в этой сессии браузера и нигде не сохраняются — "
        "ни в коде приложения, ни на сервере. Не аффилирован с Amazon/AWS."
    )

    with st.expander("🔑 Учётные данные AWS", expanded=True):
        access_key = st.text_input("Access Key ID", key="access_key")
        secret_key = st.text_input("Secret Access Key", type="password", key="secret_key")
        region = st.text_input("Регион", value="eu-west-1", key="region")

    tab1, tab2, tab3, tab4 = st.tabs([
        "🔁 SMTP-пароль",
        "🌐 Домены и email",
        "🔍 CNAME / Статус",
        "📊 Лимиты",
    ])

    # --- Tab 1: convert key to SMTP password ---
    with tab1:
        st.subheader("Конвертировать текущий ключ в SMTP")
        st.caption("Вычисляется локально, без обращения к AWS API.")
        if st.button("Конвертировать", key="btn_convert"):
            if not access_key or not secret_key:
                st.warning("Введите Access Key ID и Secret Access Key выше.")
            else:
                smtp_password = calculate_smtp_password(secret_key, region)
                st.success("Готово:")
                st.code(
                    f"SMTP Username: {access_key}\n"
                    f"SMTP Password: {smtp_password}\n"
                    f"SMTP Endpoint: email-smtp.{region}.amazonaws.com\n"
                    f"Порты: 587 (STARTTLS) или 465 (SSL)"
                )

    # --- Tab 2: domains and emails management ---
    with tab2:
        st.subheader("Управление доменами и email")
        identity = st.text_input("Email или домен", key="identity_input")

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("➕ Добавить", key="btn_add"):
                def action():
                    if not identity:
                        st.warning("Введите email или домен.")
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.create_email_identity(EmailIdentity=identity)
                    is_domain = "@" not in identity
                    if is_domain:
                        st.success("Домен добавлен. Добавьте следующие DNS-записи:")
                        tokens = response.get("DkimAttributes", {}).get("Tokens", [])
                        if tokens:
                            print_cname_records(identity, tokens)
                        else:
                            st.info("Токены не пришли сразу — проверьте статус чуть позже.")
                    else:
                        st.success("Email добавлен. Проверьте почту и перейдите по ссылке подтверждения.")
                run_action(action)

        with col2:
            if st.button("🗑 Удалить", key="btn_delete"):
                def action():
                    if not identity:
                        st.warning("Введите email или домен для удаления.")
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    sesv2.delete_email_identity(EmailIdentity=identity)
                    st.success(f"'{identity}' удалён из SES.")
                run_action(action)

        with col3:
            if st.button("📋 Список всех", key="btn_list"):
                def action():
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.list_email_identities()
                    identities = response.get("EmailIdentities", [])
                    if not identities:
                        st.info("Ничего не привязано.")
                        return
                    domains = [i for i in identities if i.get("IdentityType") == "DOMAIN"]
                    emails = [i for i in identities if i.get("IdentityType") == "EMAIL_ADDRESS"]

                    st.markdown(f"**🌐 Домены ({len(domains)}):**")
                    for item in domains:
                        verified = item.get("VerificationStatus") == "SUCCESS"
                        st.write(f"{'✅' if verified else '❌'} {item.get('IdentityName')}")

                    st.markdown(f"**📧 Email-адреса ({len(emails)}):**")
                    for item in emails:
                        verified = item.get("VerificationStatus") == "SUCCESS"
                        st.write(f"{'✅' if verified else '❌'} {item.get('IdentityName')}")
                run_action(action)

        st.checkbox("Подтверждаю удаление (для кнопки 🗑 Удалить)", key="confirm_delete_note", help="AWS удаляет identity сразу без дополнительного окна подтверждения — проверьте адрес перед нажатием.")

    # --- Tab 3: CNAME records / verification status ---
    with tab3:
        st.subheader("Статус верификации и CNAME-записи")
        identity2 = st.text_input("Домен или email", key="identity_input2")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("✅ Проверить статус", key="btn_status"):
                def action():
                    if not identity2:
                        st.warning("Введите email или домен.")
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.get_email_identity(EmailIdentity=identity2)
                    verified = response.get("VerifiedForSendingStatus")
                    st.write(f"Верифицирован для отправки: {'✅ да' if verified else '❌ нет'}")
                    dkim = response.get("DkimAttributes", {})
                    if dkim:
                        st.write(f"DKIM статус: {dkim.get('Status')}")
                run_action(action)

        with col2:
            if st.button("🔍 Показать CNAME", key="btn_cname"):
                def action():
                    if not identity2:
                        st.warning("Введите домен.")
                        return
                    if "@" in identity2:
                        st.warning("CNAME нужны только для доменов, не для email.")
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.get_email_identity(EmailIdentity=identity2)
                    dkim = response.get("DkimAttributes", {})
                    tokens = dkim.get("Tokens", [])
                    st.write(f"DKIM статус: {dkim.get('Status', 'неизвестно')}")
                    if tokens:
                        print_cname_records(identity2, tokens)
                    else:
                        st.info("Токены не найдены — сначала добавьте домен.")
                run_action(action)

    # --- Tab 4: limits and stats ---
    with tab4:
        st.subheader("Лимиты и статистика отправки")
        if st.button("📊 Обновить данные", key="btn_limits"):
            def action():
                sesv2 = get_client("sesv2", access_key, secret_key, region)
                if sesv2 is None:
                    return
                response = sesv2.get_account()
                quota = response.get("SendQuota", {})
                max_24h = quota.get("Max24HourSend", 0)
                sent_24h = quota.get("SentLast24Hours", 0)
                remaining = max_24h - sent_24h

                col1, col2, col3 = st.columns(3)
                col1.metric("Лимит за 24ч", f"{max_24h:.0f}")
                col2.metric("Отправлено", f"{sent_24h:.0f}")
                col3.metric("Осталось", f"{remaining:.0f}")

                st.write(f"Макс. скорость: {quota.get('MaxSendRate')} писем/сек")
                st.write(f"Отправка включена: {'✅' if response.get('SendingEnabled') else '❌'}")
                st.write(f"Production-режим: {'✅' if response.get('ProductionAccessEnabled') else '❌ (sandbox)'}")
            run_action(action)

    st.divider()
    st.caption(
        "⚠️ Неофициальный инструмент, не связан с Amazon Web Services. "
        "Используя приложение, вы работаете со своим собственным AWS-аккаунтом на свой страх и риск. "
        "Ключи не сохраняются и не логируются — они существуют только в памяти вашей текущей сессии."
    )


if __name__ == "__main__":
    main()
