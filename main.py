#!/usr/bin/env python3
"""
POP3 to Gmail Importer - Main Program
Automatically imports emails from POP3 to Gmail using Gmail API
Version: 3.0

This version uses Gmail API messages.import() to directly import emails into Gmail,
avoiding SPF/DKIM/DMARC issues completely.
"""

import os
import sys
import ssl
import time
import json
import base64
import signal
import logging
import poplib
import hashlib
import threading
from datetime import datetime, timedelta
from email import message_from_bytes
from email.utils import parsedate_to_datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv

# Gmail API imports
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Gmail API scope - minimal permission for import only
SCOPES = ['https://www.googleapis.com/auth/gmail.insert']

# Global flag for graceful shutdown
shutdown_requested = False
shutdown_event = threading.Event()


def signal_handler(signum, frame):
    """Handle shutdown signals (SIGINT/Ctrl+C)"""
    global shutdown_requested
    logging.info("Shutdown signal received. Finishing current operation...")
    shutdown_requested = True
    shutdown_event.set()  # Wake up from sleep immediately


def setup_logging():
    """Setup logging configuration"""
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_file = os.getenv('LOG_FILE', 'logs/pop3_gmail_importer.log')
    log_max_bytes = int(os.getenv('LOG_MAX_BYTES', 10485760))  # 10MB
    log_backup_count = int(os.getenv('LOG_BACKUP_COUNT', 5))

    # Create logs directory
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o700)

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))

    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=log_max_bytes,
        backupCount=log_backup_count
    )
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    logging.info("Logging initialized (v3.0 - Gmail API)")


def mask_password(password):
    """Mask password for log output"""
    return "***"


def mask_email(email):
    """Partially mask email address for log output"""
    if not email or '@' not in email:
        return email
    parts = email.split('@')
    return f"{parts[0][:1]}***@{parts[1]}"


def get_env_bool(key, default=True):
    """Get boolean value from environment variable"""
    value = os.getenv(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')


def get_env_int(key, default):
    """Get integer value from environment variable"""
    try:
        return int(os.getenv(key, default))
    except ValueError:
        return default




def get_gmail_service(account_num, credentials_file, token_file, target_email):
    """
    Authenticate with Gmail API and return service object.

    Args:
        account_num: Account number for logging
        credentials_file: Path to credentials.json
        token_file: Path to token file
        target_email: Target Gmail address for logging

    Returns:
        Gmail API service object or None on failure
    """
    creds = None
    token_path = Path(token_file)

    # Create tokens directory if needed
    token_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Load existing token if available
    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
            logging.debug(f"Account {account_num}: Loaded existing token from {token_file}")
        except Exception as e:
            logging.warning(f"Account {account_num}: Failed to load token: {e}")
            creds = None

    # Refresh or obtain new credentials
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logging.info(f"Account {account_num}: Token refreshed for {mask_email(target_email)}")
            except Exception as e:
                logging.error(f"Account {account_num}: Token refresh failed: {e}")
                creds = None

        if not creds:
            # Need to do OAuth flow
            if not Path(credentials_file).exists():
                logging.error(f"Account {account_num}: Credentials file not found: {credentials_file}")
                return None

            try:
                flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                logging.info(f"Account {account_num}: Starting OAuth flow for {mask_email(target_email)}...")
                logging.info("Browser will open for authentication. Please approve the access.")
                creds = flow.run_local_server(port=0)
                logging.info(f"Account {account_num}: OAuth authentication successful")
            except Exception as e:
                logging.error(f"Account {account_num}: OAuth flow failed: {e}")
                return None

        # Save credentials
        try:
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
            os.chmod(token_path, 0o600)
            logging.info(f"Account {account_num}: Token saved to {token_file}")
        except Exception as e:
            logging.error(f"Account {account_num}: Failed to save token: {e}")

    # Build Gmail service
    try:
        service = build('gmail', 'v1', credentials=creds)
        logging.debug(f"Account {account_num}: Gmail service created")
        return service
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to create Gmail service: {e}")
        return None


def import_to_gmail(service, raw_email, account_num, target_email):
    """
    Import email to Gmail using messages.import API.

    Args:
        service: Gmail API service object
        raw_email: Raw email bytes (RFC 822 format)
        account_num: Account number for logging
        target_email: Target Gmail address for logging

    Returns:
        True if successful, False otherwise
    """
    try:
        # Encode email to base64url
        encoded_message = base64.urlsafe_b64encode(raw_email).decode('utf-8')

        # Call messages.import API
        # labelIds ensures emails appear as UNREAD in INBOX (not archived/read)
        message = service.users().messages().import_(
            userId='me',
            body={
                'raw': encoded_message,
                'labelIds': ['INBOX', 'UNREAD']
            },
            internalDateSource='dateHeader'  # Preserve original date
        ).execute()

        message_id = message.get('id')
        logging.info(f"Account {account_num}: Successfully imported to Gmail (ID: {message_id}, target: {mask_email(target_email)})")
        return True

    except HttpError as e:
        logging.error(f"Account {account_num}: Gmail API error: {e}")
        return False
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to import to Gmail: {e}")
        return False


def connect_pop3(account_num, config):
    """Connect to POP3 server"""
    host = config['pop3_host']
    port = config['pop3_port']
    use_ssl = config['pop3_use_ssl']
    verify_cert = config['pop3_verify_cert']
    username = config['pop3_username']
    password = config['pop3_password']

    logging.info(f"Account {account_num}: Connecting to POP3 {host}:{port} (SSL: {use_ssl})")

    try:
        if use_ssl:
            # Create SSL context
            context = ssl.create_default_context()
            if not verify_cert:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                logging.warning(f"Account {account_num}: TLS certificate verification disabled")

            pop3 = poplib.POP3_SSL(host, port, context=context, timeout=30)
        else:
            pop3 = poplib.POP3(host, port, timeout=30)

        # Authenticate
        pop3.user(username)
        pop3.pass_(password)

        logging.info(f"Account {account_num}: POP3 authentication successful (user: {mask_email(username)})")
        return pop3

    except Exception as e:
        logging.error(f"Account {account_num}: POP3 connection failed: {e}")
        return None


def load_uidl_state(account_num, state_dir):
    """Load UIDL state from file"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"
    state = {}

    if state_file.exists():
        try:
            with open(state_file, 'r') as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        state[record['uidl']] = record
            logging.debug(f"Account {account_num}: Loaded {len(state)} UIDL records")
        except Exception as e:
            logging.error(f"Account {account_num}: Failed to load UIDL state: {e}")

    return state


def save_uidl_record(account_num, state_dir, uidl, gmail_target, backup_file):
    """Append UIDL record to state file"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"

    # Create state directory
    state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    record = {
        'uidl': uidl,
        'timestamp': datetime.now().isoformat(),
        'gmail_target': gmail_target,
        'backup_file': backup_file
    }

    try:
        with open(state_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
        os.chmod(state_file, 0o600)
        logging.debug(f"Account {account_num}: UIDL record saved: {uidl[:20]}...")
        return True
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to save UIDL record: {e}")
        return False


def save_backup(raw_email, backup_dir, account_num):
    """
    Save email to backup directory as .eml file.

    Returns:
        backup_file path on success, None on failure
    """
    if not backup_dir:
        return None

    backup_path = Path(backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Try to get Message-ID from email
    try:
        msg = message_from_bytes(raw_email)
        message_id = msg.get('Message-ID', '')
        if message_id:
            hash_value = hashlib.sha256(message_id.encode()).hexdigest()[:16]
        else:
            hash_value = hashlib.sha256(raw_email).hexdigest()[:16]
    except:
        hash_value = hashlib.sha256(raw_email).hexdigest()[:16]

    filename = f"{timestamp}_{hash_value}.eml"
    backup_file = backup_path / filename

    try:
        with open(backup_file, 'wb') as f:
            f.write(raw_email)
        os.chmod(backup_file, 0o600)
        logging.debug(f"Account {account_num}: Backup saved: {filename}")
        return str(backup_file)
    except Exception as e:
        logging.warning(f"Account {account_num}: Backup failed: {e}")
        return None


def cleanup_old_files(directory, retention_days, account_num, file_type="backup"):
    """Delete files older than retention_days"""
    if not directory or not Path(directory).exists():
        return

    cutoff_date = datetime.now() - timedelta(days=retention_days)
    deleted_count = 0

    try:
        for file_path in Path(directory).iterdir():
            if file_path.is_file():
                file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                if file_mtime < cutoff_date:
                    file_path.unlink()
                    deleted_count += 1

        if deleted_count > 0:
            logging.info(f"Account {account_num}: Deleted {deleted_count} old {file_type} files (>{retention_days} days)")
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to cleanup old files: {e}")


def cleanup_old_uidl_records(account_num, state_dir, retention_days):
    """Remove UIDL records older than retention_days"""
    state_file = Path(state_dir) / f"account{account_num}_uidl.jsonl"

    if not state_file.exists():
        return

    cutoff_date = datetime.now() - timedelta(days=retention_days)
    kept_records = []
    removed_count = 0

    try:
        with open(state_file, 'r') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    record_date = datetime.fromisoformat(record['timestamp'])
                    if record_date >= cutoff_date:
                        kept_records.append(line)
                    else:
                        removed_count += 1

        # Rewrite file with kept records
        with open(state_file, 'w') as f:
            f.writelines(kept_records)
        os.chmod(state_file, 0o600)

        if removed_count > 0:
            logging.info(f"Account {account_num}: Cleaned up {removed_count} old UIDL records (>{retention_days} days)")
    except Exception as e:
        logging.error(f"Account {account_num}: Failed to cleanup UIDL records: {e}")


def process_account(account_num):
    """Process emails for one account"""
    prefix = f"ACCOUNT{account_num}_"

    # Check if account is enabled
    if not get_env_bool(f"{prefix}ENABLED", False):
        logging.debug(f"Account {account_num}: Skipped (disabled)")
        return

    logging.info(f"Account {account_num}: Processing started")

    # Load configuration
    config = {
        'pop3_host': os.getenv(f"{prefix}POP3_HOST"),
        'pop3_port': get_env_int(f"{prefix}POP3_PORT", 995),
        'pop3_use_ssl': get_env_bool(f"{prefix}POP3_USE_SSL", True),
        'pop3_verify_cert': get_env_bool(f"{prefix}POP3_VERIFY_CERT", True),
        'pop3_username': os.getenv(f"{prefix}POP3_USERNAME"),
        'pop3_password': os.getenv(f"{prefix}POP3_PASSWORD"),
        'gmail_credentials_file': os.getenv(f"{prefix}GMAIL_CREDENTIALS_FILE"),
        'gmail_token_file': os.getenv(f"{prefix}GMAIL_TOKEN_FILE"),
        'gmail_target_email': os.getenv(f"{prefix}GMAIL_TARGET_EMAIL"),
        'delete_after_forward': get_env_bool(f"{prefix}DELETE_AFTER_FORWARD", False),
        'backup_enabled': get_env_bool(f"{prefix}BACKUP_ENABLED", True),
        'backup_dir': os.getenv(f"{prefix}BACKUP_DIR"),
        'backup_retention_days': get_env_int(f"{prefix}BACKUP_RETENTION_DAYS", 90)
    }

    # Validate required settings
    required = ['pop3_host', 'pop3_username', 'pop3_password',
                'gmail_credentials_file', 'gmail_token_file', 'gmail_target_email']
    for key in required:
        if not config[key]:
            logging.error(f"Account {account_num}: Missing required setting: {key}")
            return

    # Connect to Gmail API
    gmail_service = get_gmail_service(
        account_num,
        config['gmail_credentials_file'],
        config['gmail_token_file'],
        config['gmail_target_email']
    )
    if not gmail_service:
        logging.error(f"Account {account_num}: Failed to authenticate with Gmail API")
        return

    # Connect to POP3
    pop3 = connect_pop3(account_num, config)
    if not pop3:
        return

    try:
        # Get message count
        num_messages = len(pop3.list()[1])
        logging.info(f"Account {account_num}: {num_messages} messages on server")

        if num_messages == 0:
            pop3.quit()
            logging.info(f"Account {account_num}: No messages to process")
            return

        # Get UIDL list
        uidl_response = pop3.uidl()
        uidl_dict = {}
        for item in uidl_response[1]:
            parts = item.decode('utf-8').split()
            msg_num = int(parts[0])
            uidl = parts[1]
            uidl_dict[msg_num] = uidl

        # Load UIDL state
        state_dir = 'state'
        uidl_state = load_uidl_state(account_num, state_dir)

        # Filter unprocessed messages
        unprocessed = []
        for msg_num, uidl in uidl_dict.items():
            if uidl not in uidl_state:
                unprocessed.append((msg_num, uidl))

        logging.info(f"Account {account_num}: {len(unprocessed)} unprocessed messages")

        # Debug mode: limit to 5 most recent emails
        if not config['delete_after_forward']:
            if len(unprocessed) > 5:
                logging.info(f"Account {account_num}: Debug mode - limiting to 5 most recent emails")
                # Get Date header for each message to sort by date
                msg_dates = []
                for msg_num, uidl in unprocessed:
                    try:
                        response = pop3.top(msg_num, 20)  # Get first 20 lines for headers
                        email_data = b'\n'.join(response[1])
                        msg = message_from_bytes(email_data)
                        date_str = str(msg.get('Date', ''))
                        if date_str:
                            try:
                                date_obj = parsedate_to_datetime(date_str)
                            except:
                                date_obj = datetime.now()
                        else:
                            date_obj = datetime.now()
                        msg_dates.append((msg_num, uidl, date_obj))
                    except:
                        msg_dates.append((msg_num, uidl, datetime.now()))

                # Sort by date descending and take top 5
                msg_dates.sort(key=lambda x: x[2], reverse=True)
                unprocessed = [(num, uidl) for num, uidl, _ in msg_dates[:5]]
                logging.info(f"Account {account_num}: Selected 5 most recent messages")

        # Process maximum emails per loop
        max_emails = get_env_int('MAX_EMAILS_PER_LOOP', 100)
        if len(unprocessed) > max_emails:
            logging.warning(f"Account {account_num}: Limiting to {max_emails} emails this loop")
            unprocessed = unprocessed[:max_emails]

        # Process each unprocessed message
        processed_count = 0
        for msg_num, uidl in unprocessed:
            if shutdown_requested:
                logging.info(f"Account {account_num}: Shutdown requested, stopping processing")
                break

            try:
                # Retrieve full message
                response = pop3.retr(msg_num)
                raw_email = b'\n'.join(response[1])

                # Parse for logging
                msg = message_from_bytes(raw_email)
                subject = str(msg.get('Subject', '(no subject)'))[:50]
                from_addr = str(msg.get('From', '(unknown)'))

                logging.info(f"Account {account_num}: Processing message {msg_num}: From={mask_email(from_addr)}, Subject={subject}")

                # Backup if enabled
                backup_file = None
                if config['backup_enabled']:
                    backup_file = save_backup(raw_email, config['backup_dir'], account_num)
                    if not backup_file:
                        logging.warning(f"Account {account_num}: Backup failed, continuing with import")

                # Import to Gmail
                success = import_to_gmail(
                    gmail_service,
                    raw_email,
                    account_num,
                    config['gmail_target_email']
                )

                if not success:
                    logging.error(f"Account {account_num}: Failed to import message {msg_num}, will retry next loop")
                    continue

                # Save UIDL record
                if not save_uidl_record(account_num, state_dir, uidl, config['gmail_target_email'], backup_file):
                    logging.error(f"Account {account_num}: Failed to save UIDL, will retry next loop")
                    continue

                # Mark for deletion if in production mode
                if config['delete_after_forward']:
                    pop3.dele(msg_num)
                    logging.debug(f"Account {account_num}: Marked message {msg_num} for deletion")
                else:
                    logging.debug(f"Account {account_num}: Debug mode - not deleting message {msg_num}")

                processed_count += 1

            except Exception as e:
                import traceback
                logging.error(f"Account {account_num}: Error processing message {msg_num}: {e}")
                logging.error(f"Account {account_num}: Traceback:\n{traceback.format_exc()}")
                continue

        # Commit deletions
        pop3.quit()
        logging.info(f"Account {account_num}: POP3 session closed (processed: {processed_count})")

        # Cleanup old files
        if config['backup_enabled']:
            cleanup_old_files(
                config['backup_dir'],
                config['backup_retention_days'],
                account_num,
                "backup"
            )

        cleanup_old_uidl_records(account_num, state_dir, config['backup_retention_days'])

        logging.info(f"Account {account_num}: Processing completed")

    except Exception as e:
        logging.error(f"Account {account_num}: Unexpected error: {e}")
        try:
            pop3.quit()
        except:
            pass


def main():
    """Main program loop"""
    # Load environment variables
    load_dotenv()

    # Setup logging
    setup_logging()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Get configuration
        account_count = get_env_int('ACCOUNT_COUNT', 1)
        check_interval = get_env_int('CHECK_INTERVAL', 300)

        logging.info(f"POP3 to Gmail Importer v3.0 started (Gmail API mode)")
        logging.info(f"Accounts: {account_count}, Check interval: {check_interval}s")

        # Main loop
        while not shutdown_requested:
            loop_start = time.time()

            # Process each account
            for account_num in range(1, account_count + 1):
                if shutdown_requested:
                    break
                process_account(account_num)

            # Sleep until next check
            if not shutdown_requested:
                loop_duration = time.time() - loop_start
                sleep_time = max(0, check_interval - loop_duration)
                logging.info(f"Loop completed in {loop_duration:.1f}s. Sleeping for {sleep_time:.1f}s...")
                # Use Event.wait() instead of time.sleep() for immediate wake on Ctrl+C
                shutdown_event.wait(timeout=sleep_time)

        logging.info("Shutdown complete")

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        raise


if __name__ == '__main__':
    main()
