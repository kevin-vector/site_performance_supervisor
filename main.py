
#!pip install google-api-python-client oauth2client pandas requests -q

import argparse
import pandas as pd
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import xml.etree.ElementTree as ET
import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv('/content/drive/My Drive/Colab Notebooks/.env')
CRUX_API_KEY = os.getenv('CRUX_API_KEY')
GSC_KEY_FILE = 'drive/MyDrive/guardian-digital-corpsite-db90a9798c03.json'
SCOPES = ['https://www.googleapis.com/auth/webmasters', 'https://www.googleapis.com/auth/indexing']
DOMAINS = ['sc-domain:linuxsecurity.com', 'sc-domain:guardiandigital.com']
OUTPUT_CSV = f'drive/MyDrive/gsc_inspection_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

def get_gsc_client(key_file, scopes):
    credentials = service_account.Credentials.from_service_account_file(key_file, scopes=scopes)
    gsc_service = build('searchconsole', 'v1', credentials=credentials)
    indexing_service = build('indexing', 'v3', credentials=credentials)
    return gsc_service, indexing_service

def fetch_urls_from_sitemap(sitemap_url, limit=None):
    try:
        response = requests.get(sitemap_url)
        response.raise_for_status()
        root = ET.fromstring(response.content)

        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        
        sitemap_urls = root.findall('ns:sitemap/ns:loc', namespace)
        if sitemap_urls:
            all_urls = []
            for sitemap in sitemap_urls[:5]:
                child_sitemap_url = sitemap.text
                print(f"Fetching child sitemap: {child_sitemap_url}")
                child_urls = fetch_urls_from_sitemap(child_sitemap_url, limit=None)
                all_urls.extend(child_urls)
        else:
            all_urls = [url.find('ns:loc', namespace).text for url in root.findall('ns:url', namespace)]

        return all_urls[:limit] if limit else all_urls
    except Exception as e:
        print(f"Error fetching sitemap {sitemap_url}: {e}")
        return []

def get_urls_to_inspect(domain):
    base_url = domain.replace('sc-domain:', 'https://')
    if 'linuxsecurity.com' in base_url:
        sitemap_url = 'https://linuxsecurity.com/sitemapindex_xml.xml'
    else:  # guardiandigital.com
        sitemap_url = 'https://guardiandigital.com/sitemap_xml.xml'
    
    print(f"Fetching URLs from sitemap: {sitemap_url}")
    urls = fetch_urls_from_sitemap(sitemap_url)
    return urls

def inspect_url(gsc_service, url, site_url):
    try:
        request = {
            'inspectionUrl': url,
            'siteUrl': site_url
        }
        response = gsc_service.urlInspection().index().inspect(body=request).execute()
        inspection_result = response.get('inspectionResult', {})
        
        return {
            'url': url,
            'indexing_state': inspection_result.get('indexStatusResult', {}).get('indexingState', 'N/A'),
            'crawl_status': inspection_result.get('indexStatusResult', {}).get('lastCrawlTime', 'N/A'),
            'mobile_usability': inspection_result.get('mobileUsabilityResult', {}).get('verdict', 'N/A')
        }
    except HttpError as e:
        print(f"Error inspecting {url}: {e}")
        return {'url': url, 'indexing_state': 'ERROR', 'crawl_status': 'ERROR', 'mobile_usability': 'ERROR'}

def get_crux_data(url, crux_api_key):
    try:
        if not crux_api_key or crux_api_key == 'YOUR_CRUX_API_KEY':
            raise ValueError("CrUX API key is not set. Please update CRUX_API_KEY.")
        
        crux_url = f"https://chromeuxreport.googleapis.com/v1/records:queryRecord?key={crux_api_key}"
        payload = {'url': url}
        response = requests.post(crux_url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        metrics = data.get('record', {}).get('metrics', {})
        lcp = metrics.get('largest_contentful_paint', {}).get('percentiles', {}).get('p75', 'N/A')
        ttfb = metrics.get('experimental_time_to_first_byte', {}).get('percentiles', {}).get('p75', 'N/A')
        cls = metrics.get('cumulative_layout_shift', {}).get('percentiles', {}).get('p75', 'N/A')
        fcp = metrics.get('first_contentful_paint', {}).get('percentiles', {}).get('p75', 'N/A')
        inp = metrics.get('interaction_to_next_paint', {}).get('percentiles', {}).get('p75', 'N/A')
        
        return {'lcp': lcp, 'ttfb': ttfb, 'cls': cls, 'fcp': fcp, 'inp': inp}
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"No CrUX data available for {url} (404 Not Found). This URL may not have enough traffic.")
            return {'lcp': 'NO_DATA', 'ttfb': 'NO_DATA', 'cls': 'NO_DATA', 'fcp': 'NO_DATA', 'inp': 'NO_DATA'}
        else:
            print(f"Error fetching CrUX data for {url}: {e}")
            return {'lcp': 'ERROR', 'ttfb': 'ERROR', 'cls': 'ERROR', 'fcp': 'ERROR', 'inp': 'ERROR'}
    except Exception as e:
        print(f"Error fetching CrUX data for {url}: {e}")
        return {'lcp': 'ERROR', 'ttfb': 'ERROR', 'cls': 'ERROR', 'fcp': 'ERROR', 'inp': 'ERROR'}

def submit_url_for_indexing(indexing_service, url):
    try:
        request = {
            'url': url,
            'type': 'URL_UPDATED'
        }
        response = indexing_service.urlNotifications().publish(body=request).execute()
        print(f"Submitted {url} for indexing: {response}")
        return True
    except HttpError as e:
        print(f"Error submitting {url} for indexing: {e}")
        return False

def main(submit_unindexed=False):
    gsc_service, indexing_service = get_gsc_client(GSC_KEY_FILE, SCOPES)
    
    all_data = []
    for domain in DOMAINS:
        print(f"Processing domain: {domain}")
        urls = get_urls_to_inspect(domain)
        
        for url in urls:
            print(f"Inspecting {url}...")
            gsc_data = inspect_url(gsc_service, url, domain)
            crux_data = get_crux_data(url, CRUX_API_KEY)
            row = {**gsc_data, **crux_data}
            all_data.append(row)
            
            if submit_unindexed and gsc_data['indexing_state'] != 'INDEXING_ALLOWED':
                print(f"{url} is not indexed. Submitting...")
                submit_url_for_indexing(indexing_service, url)
    
    df = pd.DataFrame(all_data)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Data saved to {OUTPUT_CSV}")

SUBMIT_UNINDEXED = False
main(submit_unindexed=SUBMIT_UNINDEXED)