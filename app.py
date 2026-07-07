"""
AWS SES Manager — веб-версия на Streamlit (RU/EN).

Запуск локально:
    pip install -r requirements.txt
    streamlit run app.py
"""

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


# ---------- AWS regions (commercial partition) ----------
# Формат: (код региона, человекочитаемое имя)
AWS_REGIONS = [
    ("us-east-1", "US East (N. Virginia)"),
    ("us-east-2", "US East (Ohio)"),
    ("us-west-1", "US West (N. California)"),
    ("us-west-2", "US West (Oregon)"),
    ("af-south-1", "Africa (Cape Town)"),
    ("ap-south-1", "Asia Pacific (Mumbai)"),
    ("ap-south-2", "Asia Pacific (Hyderabad)"),
    ("ap-northeast-1", "Asia Pacific (Tokyo)"),
    ("ap-northeast-2", "Asia Pacific (Seoul)"),
    ("ap-northeast-3", "Asia Pacific (Osaka)"),
    ("ap-southeast-1", "Asia Pacific (Singapore)"),
    ("ap-southeast-2", "Asia Pacific (Sydney)"),
    ("ap-southeast-3", "Asia Pacific (Jakarta)"),
    ("ap-southeast-5", "Asia Pacific (Malaysia)"),
    ("ca-central-1", "Canada (Central)"),
    ("ca-west-1", "Canada West (Calgary)"),
    ("eu-central-1", "Europe (Frankfurt)"),
    ("eu-central-2", "Europe (Zurich)"),
    ("eu-west-1", "Europe (Ireland)"),
    ("eu-west-2", "Europe (London)"),
    ("eu-west-3", "Europe (Paris)"),
    ("eu-north-1", "Europe (Stockholm)"),
    ("eu-south-1", "Europe (Milan)"),
    ("me-south-1", "Middle East (Bahrain)"),
    ("me-central-1", "Middle East (UAE)"),
    ("il-central-1", "Israel (Tel Aviv)"),
    ("sa-east-1", "South America (São Paulo)"),
]

REGION_LABELS = [f"{code} — {name}" for code, name in AWS_REGIONS]
REGION_CODE_BY_LABEL = {f"{code} — {name}": code for code, name in AWS_REGIONS}


# ---------- Translations ----------

TEXTS = {
    "ru": {
        "title": "📧 AWS SES Manager",
        "subtitle": (
            "Бесплатный инструмент для управления AWS SES. "
            "Ваши AWS-ключи используются только в этой сессии браузера и нигде не сохраняются — "
            "ни в коде приложения, ни на сервере. Не аффилирован с Amazon/AWS."
        ),
        "credentials_header": "🔑 Учётные данные AWS",
        "access_key": "Access Key ID",
        "secret_key": "Secret Access Key",
        "region": "Регион",
        "tab_smtp": "🔁 SMTP-пароль",
        "tab_domains": "🌐 Домены и email",
        "tab_cname": "🔍 CNAME / Статус",
        "tab_limits": "📊 Лимиты",
        "smtp_header": "Конвертировать текущий ключ в SMTP",
        "smtp_caption": "Вычисляется локально, без обращения к AWS API.",
        "convert_btn": "Конвертировать",
        "enter_keys_warn": "Введите Access Key ID и Secret Access Key выше.",
        "done": "Готово:",
        "domains_header": "Управление доменами и email",
        "identity_label": "Email или домен",
        "add_btn": "➕ Добавить",
        "delete_btn": "🗑 Удалить",
        "list_btn": "📋 Список всех",
        "enter_identity_warn": "Введите email или домен.",
        "domain_added": "Домен добавлен. Добавьте следующие DNS-записи:",
        "email_added": "Email добавлен. Проверьте почту и перейдите по ссылке подтверждения.",
        "tokens_delayed": "Токены не пришли сразу — проверьте статус чуть позже.",
        "enter_identity_delete_warn": "Введите email или домен для удаления.",
        "deleted": "удалён из SES.",
        "nothing_attached": "Ничего не привязано.",
        "domains_count": "🌐 Домены",
        "emails_count": "📧 Email-адреса",
        "cname_header": "Статус верификации и CNAME-записи",
        "identity_label2": "Домен или email",
        "check_status_btn": "✅ Проверить статус",
        "show_cname_btn": "🔍 Показать CNAME",
        "verified_sending": "Верифицирован для отправки",
        "yes": "да",
        "no": "нет",
        "dkim_status": "DKIM статус",
        "cname_only_domains": "CNAME нужны только для доменов, не для email.",
        "tokens_not_found": "Токены не найдены — сначала добавьте домен.",
        "limits_header": "Лимиты и статистика отправки",
        "update_btn": "📊 Обновить данные",
        "limit_24h": "Лимит за 24ч",
        "sent": "Отправлено",
        "remaining": "Осталось",
        "max_rate": "Макс. скорость",
        "per_sec": "писем/сек",
        "sending_enabled": "Отправка включена",
        "production_mode": "Production-режим",
        "sandbox": "(sandbox)",
        "footer": (
            "⚠️ Неофициальный инструмент, не связан с Amazon Web Services. "
            "Используя приложение, вы работаете со своим собственным AWS-аккаунтом на свой страх и риск. "
            "Ключи не сохраняются и не логируются — они существуют только в памяти вашей текущей сессии."
        ),
        "help_smtp": (
            "**Как это работает:** введите ваш Access Key ID и Secret Access Key в поле выше, "
            "выберите регион и нажмите «Конвертировать». Приложение локально вычислит SMTP-пароль "
            "по официальному алгоритму AWS — никакого обращения к AWS API для этого не требуется. "
            "Полученные SMTP Username/Password можно использовать в любом почтовом клиенте или "
            "SMTP-библиотеке (например, PHPMailer, Nodemailer, smtplib) для отправки писем через SES."
        ),
        "help_domains": (
            "**Как это работает:** введите email-адрес или домен и нажмите «Добавить» — SES начнёт "
            "процесс верификации (для email придёт письмо со ссылкой, для домена вернутся DNS-записи "
            "для добавления в DNS). Кнопка «Список всех» покажет все ранее добавленные домены и email "
            "с их статусом верификации. Кнопка «Удалить» отвязывает identity от SES — при повторном "
            "добавлении верификацию нужно будет пройти заново."
        ),
        "help_cname": (
            "**Как это работает:** введите домен (для email эта вкладка не нужна — там верификация "
            "идёт по ссылке в письме) и нажмите «Проверить статус», чтобы увидеть текущее состояние "
            "верификации и DKIM. Кнопка «Показать CNAME» выведет все DNS-записи, которые нужно "
            "добавить у регистратора домена — тип, имя и значение каждой записи. После добавления "
            "записей верификация проходит автоматически, обычно от нескольких минут до пары часов."
        ),
        "help_limits": (
            "**Как это работает:** нажмите «Обновить данные», чтобы увидеть текущую квоту отправки — "
            "сколько писем можно отправить за 24 часа, сколько уже отправлено и сколько осталось. "
            "Также показывается максимальная скорость отправки (писем в секунду) и включён ли "
            "production-режим (если аккаунт всё ещё в sandbox — письма можно слать только на "
            "верифицированные адреса)."
        ),
        "no_creds_error": "Не удалось аутентифицироваться. Проверьте ключи.",
        "aws_error": "AWS ошибка",
        "generic_error": "Ошибка",
        "boto3_missing": "boto3 не установлен. Добавьте его в requirements.txt",
    },
    "en": {
        "title": "📧 AWS SES Manager",
        "subtitle": (
            "A free tool for managing AWS SES. "
            "Your AWS keys are used only within this browser session and are never stored — "
            "not in the app code, not on the server. Not affiliated with Amazon/AWS."
        ),
        "credentials_header": "🔑 AWS Credentials",
        "access_key": "Access Key ID",
        "secret_key": "Secret Access Key",
        "region": "Region",
        "tab_smtp": "🔁 SMTP Password",
        "tab_domains": "🌐 Domains & Emails",
        "tab_cname": "🔍 CNAME / Status",
        "tab_limits": "📊 Limits",
        "smtp_header": "Convert current key to SMTP",
        "smtp_caption": "Calculated locally, no AWS API call involved.",
        "convert_btn": "Convert",
        "enter_keys_warn": "Enter Access Key ID and Secret Access Key above.",
        "done": "Done:",
        "domains_header": "Manage domains and emails",
        "identity_label": "Email or domain",
        "add_btn": "➕ Add",
        "delete_btn": "🗑 Delete",
        "list_btn": "📋 List all",
        "enter_identity_warn": "Enter an email or domain.",
        "domain_added": "Domain added. Add the following DNS records:",
        "email_added": "Email added. Check your inbox and click the confirmation link.",
        "tokens_delayed": "Tokens didn't arrive immediately — check status again shortly.",
        "enter_identity_delete_warn": "Enter an email or domain to delete.",
        "deleted": "removed from SES.",
        "nothing_attached": "Nothing attached yet.",
        "domains_count": "🌐 Domains",
        "emails_count": "📧 Email addresses",
        "cname_header": "Verification status and CNAME records",
        "identity_label2": "Domain or email",
        "check_status_btn": "✅ Check status",
        "show_cname_btn": "🔍 Show CNAME",
        "verified_sending": "Verified for sending",
        "yes": "yes",
        "no": "no",
        "dkim_status": "DKIM status",
        "cname_only_domains": "CNAME records are only needed for domains, not emails.",
        "tokens_not_found": "Tokens not found — add the domain first.",
        "limits_header": "Sending limits and statistics",
        "update_btn": "📊 Refresh data",
        "limit_24h": "24h limit",
        "sent": "Sent",
        "remaining": "Remaining",
        "max_rate": "Max rate",
        "per_sec": "emails/sec",
        "sending_enabled": "Sending enabled",
        "production_mode": "Production mode",
        "sandbox": "(sandbox)",
        "footer": (
            "⚠️ Unofficial tool, not affiliated with Amazon Web Services. "
            "By using this app you operate on your own AWS account at your own risk. "
            "Keys are never stored or logged — they exist only in your current session's memory."
        ),
        "help_smtp": (
            "**How it works:** enter your Access Key ID and Secret Access Key above, pick a region, "
            "and click Convert. The app computes the SMTP password locally using AWS's official "
            "algorithm — no AWS API call is made. Use the resulting SMTP Username/Password in any "
            "email client or SMTP library (e.g. PHPMailer, Nodemailer, smtplib) to send mail through SES."
        ),
        "help_domains": (
            "**How it works:** enter an email address or domain and click Add — SES starts the "
            "verification process (an email gets a confirmation link, a domain returns DNS records "
            "to add). The List all button shows every domain/email you've added along with its "
            "verification status. Delete removes the identity from SES — verification has to be "
            "redone if you add it again later."
        ),
        "help_cname": (
            "**How it works:** enter a domain (this tab isn't needed for emails — those verify via "
            "a link sent to the inbox) and click Check status to see the current verification and "
            "DKIM state. Show CNAME lists every DNS record you need to add at your domain registrar — "
            "type, name, and value for each. Verification completes automatically once the records "
            "propagate, usually within minutes to a couple of hours."
        ),
        "help_limits": (
            "**How it works:** click Refresh data to see your current sending quota — how many "
            "emails you can send per 24 hours, how many you've already sent, and how many remain. "
            "It also shows the maximum send rate (emails/sec) and whether production access is "
            "enabled (while in sandbox mode, you can only send to verified addresses)."
        ),
        "no_creds_error": "Authentication failed. Check your keys.",
        "aws_error": "AWS error",
        "generic_error": "Error",
        "boto3_missing": "boto3 is not installed. Add it to requirements.txt",
    },
}


def t(key):
    lang = st.session_state.get("lang", "ru")
    return TEXTS[lang].get(key, key)


# ---------- AWS client helper ----------

def get_client(service, access_key, secret_key, region):
    if boto3 is None:
        st.error(t("boto3_missing"))
        return None
    if not access_key or not secret_key:
        st.warning(t("enter_keys_warn"))
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
        st.markdown(f"**{i}:**")
        st.code(f"Type:  CNAME\nName:  {record_name}\nValue: {record_value}")


def run_action(func):
    try:
        func()
    except NoCredentialsError:
        st.error(t("no_creds_error"))
    except ClientError as e:
        st.error(f"{t('aws_error')}: {e.response['Error']['Code']} — {e.response['Error']['Message']}")
    except Exception as e:
        st.error(f"{t('generic_error')}: {e}")


# ---------- Main app ----------

def main():
    st.set_page_config(page_title="AWS SES Manager", page_icon="📧", layout="wide")

    st.markdown(
        """
        <style>
        .block-container {
            max-width: 1000px;
            padding-left: 3rem;
            padding-right: 3rem;
            margin: 0 auto;
        }
        pre, code {
            white-space: pre-wrap !important;
            word-break: break-all !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if "lang" not in st.session_state:
        st.session_state["lang"] = "ru"

    # Language switcher
    col_lang, _ = st.columns([1, 4])
    with col_lang:
        lang_choice = st.selectbox(
            "🌐", ["Русский", "English"],
            index=0 if st.session_state["lang"] == "ru" else 1,
            label_visibility="collapsed",
        )
    st.session_state["lang"] = "ru" if lang_choice == "Русский" else "en"

    st.title(t("title"))
    st.caption(t("subtitle"))

    with st.expander(t("credentials_header"), expanded=True):
        access_key = st.text_input(t("access_key"), key="access_key")
        secret_key = st.text_input(t("secret_key"), type="password", key="secret_key")
        default_index = next(
            (i for i, l in enumerate(REGION_LABELS) if l.startswith("eu-west-1")), 0
        )
        region_label = st.selectbox(t("region"), REGION_LABELS, index=default_index)
        region = REGION_CODE_BY_LABEL[region_label]

    tab1, tab2, tab3, tab4 = st.tabs([
        t("tab_smtp"), t("tab_domains"), t("tab_cname"), t("tab_limits"),
    ])

    # --- Tab 1: convert key to SMTP password ---
    with tab1:
        st.subheader(t("smtp_header"))
        st.caption(t("smtp_caption"))
        if st.button(t("convert_btn"), key="btn_convert"):
            if not access_key or not secret_key:
                st.warning(t("enter_keys_warn"))
            else:
                smtp_password = calculate_smtp_password(secret_key, region)
                st.success(t("done"))
                st.code(
                    f"SMTP Username: {access_key}\n"
                    f"SMTP Password: {smtp_password}\n"
                    f"SMTP Endpoint: email-smtp.{region}.amazonaws.com\n"
                    f"Ports: 587 (STARTTLS) or 465 (SSL)"
                )
        st.info(t("help_smtp"))

    # --- Tab 2: domains and emails management ---
    with tab2:
        st.subheader(t("domains_header"))
        identity = st.text_input(t("identity_label"), key="identity_input")

        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button(t("add_btn"), key="btn_add"):
                def action():
                    if not identity:
                        st.warning(t("enter_identity_warn"))
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.create_email_identity(EmailIdentity=identity)
                    is_domain = "@" not in identity
                    if is_domain:
                        st.success(t("domain_added"))
                        tokens = response.get("DkimAttributes", {}).get("Tokens", [])
                        if tokens:
                            print_cname_records(identity, tokens)
                        else:
                            st.info(t("tokens_delayed"))
                    else:
                        st.success(t("email_added"))
                run_action(action)

        with col2:
            if st.button(t("delete_btn"), key="btn_delete"):
                def action():
                    if not identity:
                        st.warning(t("enter_identity_delete_warn"))
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    sesv2.delete_email_identity(EmailIdentity=identity)
                    st.success(f"'{identity}' {t('deleted')}")
                run_action(action)

        with col3:
            if st.button(t("list_btn"), key="btn_list"):
                def action():
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.list_email_identities()
                    identities = response.get("EmailIdentities", [])
                    if not identities:
                        st.info(t("nothing_attached"))
                        return
                    domains = [i for i in identities if i.get("IdentityType") == "DOMAIN"]
                    emails = [i for i in identities if i.get("IdentityType") == "EMAIL_ADDRESS"]

                    st.markdown(f"**{t('domains_count')} ({len(domains)}):**")
                    for item in domains:
                        verified = item.get("VerificationStatus") == "SUCCESS"
                        st.write(f"{'✅' if verified else '❌'} {item.get('IdentityName')}")

                    st.markdown(f"**{t('emails_count')} ({len(emails)}):**")
                    for item in emails:
                        verified = item.get("VerificationStatus") == "SUCCESS"
                        st.write(f"{'✅' if verified else '❌'} {item.get('IdentityName')}")
                run_action(action)

        st.info(t("help_domains"))

    # --- Tab 3: CNAME records / verification status ---
    with tab3:
        st.subheader(t("cname_header"))
        identity2 = st.text_input(t("identity_label2"), key="identity_input2")

        col1, col2 = st.columns(2)

        with col1:
            if st.button(t("check_status_btn"), key="btn_status"):
                def action():
                    if not identity2:
                        st.warning(t("enter_identity_warn"))
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.get_email_identity(EmailIdentity=identity2)
                    verified = response.get("VerifiedForSendingStatus")
                    st.write(f"{t('verified_sending')}: {'✅ ' + t('yes') if verified else '❌ ' + t('no')}")
                    dkim = response.get("DkimAttributes", {})
                    if dkim:
                        st.write(f"{t('dkim_status')}: {dkim.get('Status')}")
                run_action(action)

        with col2:
            if st.button(t("show_cname_btn"), key="btn_cname"):
                def action():
                    if not identity2:
                        st.warning(t("enter_identity_warn"))
                        return
                    if "@" in identity2:
                        st.warning(t("cname_only_domains"))
                        return
                    sesv2 = get_client("sesv2", access_key, secret_key, region)
                    if sesv2 is None:
                        return
                    response = sesv2.get_email_identity(EmailIdentity=identity2)
                    dkim = response.get("DkimAttributes", {})
                    tokens = dkim.get("Tokens", [])
                    st.write(f"{t('dkim_status')}: {dkim.get('Status', '—')}")
                    if tokens:
                        print_cname_records(identity2, tokens)
                    else:
                        st.info(t("tokens_not_found"))
                run_action(action)

        st.info(t("help_cname"))

    # --- Tab 4: limits and stats ---
    with tab4:
        st.subheader(t("limits_header"))
        if st.button(t("update_btn"), key="btn_limits"):
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
                col1.metric(t("limit_24h"), f"{max_24h:.0f}")
                col2.metric(t("sent"), f"{sent_24h:.0f}")
                col3.metric(t("remaining"), f"{remaining:.0f}")

                st.write(f"{t('max_rate')}: {quota.get('MaxSendRate')} {t('per_sec')}")
                st.write(f"{t('sending_enabled')}: {'✅' if response.get('SendingEnabled') else '❌'}")
                production = response.get('ProductionAccessEnabled')
                st.write(f"{t('production_mode')}: {'✅' if production else '❌ ' + t('sandbox')}")
            run_action(action)

        st.info(t("help_limits"))

    st.divider()
    st.caption(t("footer"))


if __name__ == "__main__":
    main()
