# !pip install google-api-python-client oauth2client pandas requests -q

import argparse
import pandas as pd
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import xml.etree.ElementTree as ET
import requests
import json
from datetime import datetime
import time
from dotenv import load_dotenv
import os

load_dotenv('/content/drive/My Drive/Colab Notebooks/.env')
CRUX_API_KEY = os.getenv('CRUX_API_KEY')
GSC_KEY_FILE = 'drive/MyDrive/guardian-digital-corpsite-db90a9798c03.json'
SCOPES = ['https://www.googleapis.com/auth/webmasters', 'https://www.googleapis.com/auth/indexing']
DOMAINS = ['sc-domain:linuxsecurity.com', 'sc-domain:guardiandigital.com']
OUTPUT_CSV = f'drive/MyDrive/gsc_inspection_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
API_DELAY = 0.2  # Delay in seconds between API calls (200ms)

# Initialize GSC API client
def get_gsc_client(key_file, scopes):
    credentials = service_account.Credentials.from_service_account_file(key_file, scopes=scopes)
    gsc_service = build('searchconsole', 'v1', credentials=credentials)
    return gsc_service

# Fetch URLs from a sitemap
def fetch_urls_from_sitemap(sitemap_url, limit=1000):
    try:
        response = requests.get(sitemap_url)
        response.raise_for_status()
        root = ET.fromstring(response.content)

        namespace = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        sitemap_urls = root.findall('ns:sitemap/ns:loc', namespace)
        if sitemap_urls:
            all_urls = []
            for sitemap in sitemap_urls:
                child_sitemap_url = sitemap.text
                print(f"Fetching child sitemap: {child_sitemap_url}")
                child_urls = fetch_urls_from_sitemap(child_sitemap_url, limit=None)
                all_urls.extend(child_urls)
                if len(all_urls) >= limit:
                    break
        else:
            all_urls = [url.find('ns:loc', namespace).text for url in root.findall('ns:url', namespace)]

        return all_urls[:limit]
    except Exception as e:
        print(f"Error fetching sitemap {sitemap_url}: {e}")
        return []

# Fetch URLs to inspect from sitemaps
def get_urls_to_inspect(domain):
    base_url = domain.replace('sc-domain:', 'https://')
    if 'linuxsecurity.com' in base_url:
        sitemap_url = 'https://linuxsecurity.com/sitemapindex_xml.xml'
    else:
        sitemap_url = 'https://guardiandigital.com/sitemap_xml.xml'
    
    print(f"Fetching URLs from sitemap: {sitemap_url}")
    urls = fetch_urls_from_sitemap(sitemap_url, limit=1000)  # Exactly 1000 URLs per domain
    if not urls:
        print(f"No URLs found in sitemap for {base_url}. Falling back to default URLs.")
        if 'linuxsecurity.com' in base_url:
            return [
                f"{base_url}/howtos/harden-my-filesystem",
                f"{base_url}/features",
                f"{base_url}/news",
                f"{base_url}"
            ]
        else:
            return [
                f"{base_url}/about",
                f"{base_url}/contact",
                f"{base_url}"
            ]
    return urls

# Inspect a URL using GSC URL Inspection API
def inspect_url(gsc_service, url, site_url):
    try:
        request = {
            'inspectionUrl': url,
            'siteUrl': site_url
        }
        response = gsc_service.urlInspection().index().inspect(body=request).execute()
        inspection_result = response.get('inspectionResult', {})
        indexing_state = inspection_result.get('indexStatusResult', {}).get('indexingState', 'N/A')
        
        is_indexing_problem = indexing_state not in ['INDEXED', 'N/A']
        
        return {
            'url': url,
            'indexing_state': indexing_state,
            'crawl_status': inspection_result.get('indexStatusResult', {}).get('lastCrawlTime', 'N/A'),
            'mobile_usability': inspection_result.get('mobileUsabilityResult', {}).get('verdict', 'N/A'),
            'indexing_problem': is_indexing_problem
        }
    except HttpError as e:
        error_message = f"Error inspecting {url}: {e}"
        print(error_message)
        if e.resp.status == 403:
            error_message += " (Permission denied - check if service account has Owner role)"
        elif e.resp.status == 429:
            error_message += " (Rate limit exceeded)"
        return {
            'url': url,
            'indexing_state': f'ERROR: {e.resp.status}',
            'crawl_status': 'ERROR',
            'mobile_usability': 'ERROR',
            'indexing_problem': True,
            'error_message': error_message
        }

# Fetch CWV data using CrUX API
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
        
        performance_problems = []
        if lcp != 'N/A' and lcp > 2500:
            performance_problems.append(f"LCP: {lcp}ms")
        if ttfb != 'N/A' and ttfb > 800:
            performance_problems.append(f"TTFB: {ttfb}ms")
        if cls != 'N/A' and cls > 0.1:
            performance_problems.append(f"CLS: {cls}")
        if fcp != 'N/A' and fcp > 1800:
            performance_problems.append(f"FCP: {fcp}ms")
        if inp != 'N/A' and inp > 200:
            performance_problems.append(f"INP: {inp}ms")
        
        return {
            'lcp': lcp,
            'ttfb': ttfb,
            'cls': cls,
            'fcp': fcp,
            'inp': inp,
            'performance_problems': '; '.join(performance_problems) if performance_problems else 'None'
        }
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"No CrUX data available for {url} (404 Not Found). This URL may not have enough traffic.")
            return {
                'lcp': 'NO_DATA',
                'ttfb': 'NO_DATA',
                'cls': 'NO_DATA',
                'fcp': 'NO_DATA',
                'inp': 'NO_DATA',
                'performance_problems': 'No CrUX data'
            }
        else:
            print(f"Error fetching CrUX data for {url}: {e}")
            return {
                'lcp': 'ERROR',
                'ttfb': 'ERROR',
                'cls': 'ERROR',
                'fcp': 'ERROR',
                'inp': 'ERROR',
                'performance_problems': 'ERROR'
            }
    except Exception as e:
        print(f"Error fetching CrUX data for {url}: {e}")
        return {
            'lcp': 'ERROR',
            'ttfb': 'ERROR',
            'cls': 'ERROR',
            'fcp': 'ERROR',
            'inp': 'ERROR',
            'performance_problems': 'ERROR'
        }

# Main function
def main():
    gsc_service = get_gsc_client(GSC_KEY_FILE, SCOPES)
    
    all_data = []
    for domain in DOMAINS:
        print(f"Processing domain: {domain}")
        urls = get_urls_to_inspect(domain)
        
        for url in urls:
            print(f"Inspecting {url}...")
            # GSC API call
            gsc_data = inspect_url(gsc_service, url, domain)
            time.sleep(API_DELAY)  # Delay after GSC API call
            
            # CrUX API call
            crux_data = get_crux_data(url, CRUX_API_KEY)
            time.sleep(API_DELAY)  # Delay after CrUX API call
            
            row = {**gsc_data, **crux_data}
            all_data.append(row)
    
    # Create DataFrame and sort by problems
    df = pd.DataFrame(all_data)
    df['priority'] = df.apply(
        lambda row: 2 if row['indexing_problem'] else 0 + (1 if row['performance_problems'] != 'None' and row['performance_problems'] != 'No CrUX data' else 0),
        axis=1
    )
    df['num_performance_issues'] = df['performance_problems'].apply(
        lambda x: len(x.split(';')) if x not in ['None', 'No CrUX data', 'ERROR'] else 0
    )
    df = df.sort_values(by=['priority', 'indexing_problem', 'num_performance_issues'], ascending=[False, False, False])
    
    df = df.drop(columns=['priority', 'num_performance_issues'])
    
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Data saved to {OUTPUT_CSV}")
    files.download(OUTPUT_CSV)

# Run the script
main()