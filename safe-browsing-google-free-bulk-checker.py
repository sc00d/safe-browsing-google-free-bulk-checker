#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import requests
import json
import logging
import time
import re
from requests.exceptions import SSLError, RequestException

# Set up logging
logging.basicConfig(
    filename='safebrowsing_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Reading domains from file
with open('domains.txt', 'r') as file:
    domains = [line.strip() for line in file if line.strip()]

# List to store dangerous domains and skipped domains
dangerous_domains = []
skipped_domains = []

def check_domain(domain, attempt=1, max_attempts=3):
    try:
        url = f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={domain}"
        response = requests.get(url, timeout=10)
        
        # Log the raw response content
        logging.info(f"Domain: {domain} (Attempt {attempt})")
        logging.info(f"Response Status Code: {response.status_code}")
        logging.info(f"Response Headers: {response.headers}")
        logging.info(f"Response Content: {response.text}")
        
        # Check for rate limiting (429)
        if response.status_code == 429:
            if attempt < max_attempts:
                logging.warning(f"Rate limit hit for {domain} (HTTP 429). Retrying after 5 seconds (Attempt {attempt}/{max_attempts}).")
                print(f"Rate limit hit for {domain}. Retrying after 5 seconds (Attempt {attempt}/{max_attempts}).")
                time.sleep(5)
                return check_domain(domain, attempt + 1, max_attempts)
            else:
                logging.warning(f"Max retries reached for {domain} (HTTP 429). Skipping.")
                print(f"Max retries reached for {domain}. Skipping.")
                skipped_domains.append(domain)
                return False
        
        # Check if response is JSON
        if response.headers.get('Content-Type', '').startswith('application/json'):
            try:
                # Strip JSONP prefix (e.g., ")]}'") if present
                response_text = re.sub(r'^\)\]\}\'\n', '', response.text)
                data = json.loads(response_text)
                
                # Check if response contains 'true'
                if 'true' in json.dumps(data).lower():
                    dangerous_domains.append(domain)
                    logging.info(f"Domain {domain} flagged as dangerous")
                    print(f"Domain {domain} flagged as dangerous")
                else:
                    logging.info(f"Domain {domain} is safe")
                    print(f"Domain {domain} is safe")
                return True
            except json.JSONDecodeError as json_err:
                logging.error(f"JSON Decode Error for {domain}: {str(json_err)}")
                logging.error(f"Response Content: {response.text}")
                print(f"Error decoding JSON for {domain}: {str(json_err)}")
                return False
        else:
            logging.error(f"Invalid Content-Type for {domain}: {response.headers.get('Content-Type')}")
            logging.error(f"Response Content: {response.text}")
            print(f"Invalid response for {domain}: Content-Type is {response.headers.get('Content-Type')}")
            return False
            
    except SSLError as ssl_err:
        if attempt < max_attempts:
            logging.warning(f"SSL Error for {domain}: {str(ssl_err)}. Retrying after 5 seconds (Attempt {attempt}/{max_attempts}).")
            print(f"SSL Error for {domain}: {str(ssl_err)}. Retrying after 5 seconds (Attempt {attempt}/{max_attempts}).")
            time.sleep(5)
            return check_domain(domain, attempt + 1, max_attempts)
        else:
            logging.error(f"Max retries reached for {domain} (SSL Error): {str(ssl_err)}")
            print(f"Max retries reached for {domain} (SSL Error): {str(ssl_err)}")
            skipped_domains.append(domain)
            return False
    except RequestException as req_err:
        logging.error(f"Request Error for {domain}: {str(req_err)}")
        print(f"Error checking {domain}: {str(req_err)}")
        return False
    except Exception as e:
        logging.error(f"Unexpected Error for {domain}: {str(e)}")
        print(f"Unexpected error for {domain}: {str(e)}")
        return False

# Checking each domain
for domain in domains:
    check_domain(domain)
    # Delay to avoid rate limiting
    time.sleep(2)

# Writing dangerous domains to file
with open('dangerdomains.txt', 'w') as file:
    for domain in dangerous_domains:
        file.write(f"{domain}\n")

# Log and print summary
logging.info(f"Found {len(dangerous_domains)} dangerous domains. Results saved to dangerdomains.txt")
logging.info(f"Skipped {len(skipped_domains)} domains due to errors: {skipped_domains}")
print(f"Found {len(dangerous_domains)} dangerous domains. Results saved to dangerdomains.txt")
print(f"Skipped {len(skipped_domains)} domains due to errors: {skipped_domains}")


# In[ ]:




