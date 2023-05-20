# a simple suspicious email analyzer
# input eml, outputs to a txt the following
# sending email address, 
# date +time,  
# subject line, 
# recipient email address, 
# reply-to-address, 
# the X-sender-IP + result of reverse DNS lookup (hostname)
# If there is an attachment - name of the file, actual file type, MD5, SHA1, and SHA256 hash. 
# If there are any hyperlinks in the eml file also outputs the url.

# Note that when the script runs you will be asked for VirusTotal API
# If it is provided the hashes will be queried in their database
# If no key is provided (blank), the script will still execute but ignore the VirusTotal query

import email
from email import policy
import hashlib
import socket
import re
import requests
import argparse
from urllib.parse import urlparse
from pathlib import Path

def process_attachment(part):
    data = part.get_payload(decode=True)
    name = part.get_filename()
    file_type = part.get_content_type()

    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    return (name, file_type, md5_hash, sha1_hash, sha256_hash)

def extract_links(text):
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    return urls

def check_virustotal(hash, api_key):
    if not api_key:
        return None, None

    url = 'https://www.virustotal.com/api/v3/files/' + hash
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        return json_response['data']['attributes']['last_analysis_stats'], json_response['data']['links']['self']
    else:
        return None, None

def parse_email(eml_path, txt_output_path, virustotal_api_key):
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
            if virustotal_api_key:
                stats, link = check_virustotal(info[4], virustotal_api_key)  # Here we are using SHA256 for VirusTotal search
                if stats and link:
                    out.write(f'    VirusTotal Stats: {stats}\n')
                    out.write(f'    VirusTotal Link: {link}\n')

        for i, url in enumerate(links, start=1):
            out.write(f'Link {i}: {url}\n')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process an EML file.')
    parser.add_argument('emlfile', type=str, help='Path to the .eml file')
    parser.add_argument('txtfile', type=str, help='Path to the output .txt file')
    parser.add_argument('--apikey', type=str, help='VirusTotal API Key', default='')
    args = parser.parse_args()

    parse_email(args.emlfile, args.txtfile, args.apikey)

      