import email
from email import policy
import hashlib
import socket
import re
from urllib.parse import urlparse
from pathlib import Path

def process_attachment(part):
    # Extracts information from an attachment
    data = part.get_payload(decode=True)
    name = part.get_filename()
    file_type = part.get_content_type()

    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    return (name, file_type, md5_hash, sha1_hash, sha256_hash)

def extract_links(text):
    # Extract URLs from the text
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    return urls

def parse_email(eml_path, txt_output_path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    from_address = msg.get('From')
    date_time = msg.get('Date')
    subject = msg.get('Subject')
    to_address = msg.get('To')
    reply_to = msg.get('Reply-To')
    x_sender_ip = msg.get('X-Sender-IP')

    hostname = socket.gethostbyaddr(x_sender_ip)[0] if x_sender_ip else None

    attachments_info = []
    links = []

    if msg.is_multipart():
        for part in msg.iter_parts():
            content_disposition = part.get('Content-Disposition')
            if content_disposition and 'attachment' in content_disposition:
                attachments_info.append(process_attachment(part))

            if part.get_content_type() == 'text/html':
                links.extend(extract_links(part.get_content()))

    with open(txt_output_path, 'w') as out:
        out.write(f'From: {from_address}\n')
        out.write(f'Date/Time: {date_time}\n')
        out.write(f'Subject: {subject}\n')
        out.write(f'To: {to_address}\n')
        out.write(f'Reply-To: {reply_to}\n')
        out.write(f'X-Sender-IP: {x_sender_ip}\n')
        out.write(f'Hostname: {hostname}\n')
        for i, info in enumerate(attachments_info, start=1):
            out.write(f'Attachment {i} - Filename: {info[0]}, File Type: {info[1]}, MD5: {info[2]}, SHA1: {info[3]}, SHA256: {info[4]}\n')
        for i, url in enumerate(links, start=1):
            out.write(f'Link {i}: {url}\n')

eml_file = Path('/path/to/your/emlfile.eml')
txt_file = Path('/path/to/your/outputfile.txt')

parse_email(eml_file, txt_file)
