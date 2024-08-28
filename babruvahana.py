import requests
from bs4 import BeautifulSoup
import re
import os
from urllib.parse import urljoin, urlparse
import argparse
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Banner for the tool
def print_banner():
    banner = f"""
    {Fore.BLUE}                 ,---.                                                        ,-.-.    ,---.       ,--.-,,-,--,    ,---.       .-._            ,---.      
    _..---.    .--.'  \         _..---.     .-.,.---.    .--.-. .-.-.  ,--.-./=/ ,/  .--.'  \     /==/  /|=|  |  .--.'  \     /==/ \  .-._   .--.'  \     
  .' .'.-. \   \==\-/\ \      .' .'.-. \   /==/  `   \  /==/ -|/=/  | /==/, ||=| -|  \==\-/\ \    |==|_ ||=|, |  \==\-/\ \    |==|, \/ /, /  \==\-/\ \    
 /==/- '=' /   /==/-|_\ |    /==/- '=' /  |==|-, .=., | |==| ,||=| -| \==\,  \ / ,|  /==/-|_\ |   |==| ,|/=| _|  /==/-|_\ |   |==|-  \|  |   /==/-|_\ |   
 |==|-,   '    \==\,   - \   |==|-,   '   |==|   '='  / |==|- | =/  |  \==\ - ' - /  \==\,   - \  |==|- `-' _ |  \==\,   - \  |==| ,  | -|   \==\,   - \  
 |==|  .=. \   /==/ -   ,|   |==|  .=. \  |==|- ,   .'  |==|,    |   \==\ ,   |   /==/ -   ,|  |==|  _     |  /==/ -   ,|  |==| -   _ |   /==/ -   ,|  
 /==/- '=' ,| /==/-  /\ - \  /==/- '=' ,| |==|_  . ,'.  |==|-   ,   /   |==| -  ,/  /==/-  /\ - \ |==|   .-. ,\ /==/-  /\ - \ |==|  /\ , |  /==/-  /\ - \ 
|==|   -   /  \==\ _.\=\.-' |==|   -   /  /==/  /\ ,  ) /==/ , _  .'    \==\  _ /   \==\ _.\=\.-' /==/, //=/  | \==\ _.\=\.-' /==/, | |- |  \==\ _.\=\.-' 
`-._`.___,'    `--`         `-._`.___,'   `--`-`--`--'  `--`..---'       `--`--'     `--`         `--`-' `-`--`  `--`         `--`./  `--`   `--`         {Style.RESET_ALL}
    """
    print(banner)

# Function to find all JavaScript files linked on the given URL
def find_js_files(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        js_files = [urljoin(url, script['src']) for script in soup.find_all('script', src=True)]
        return js_files, soup
    except requests.RequestException as e:
        print(f"{Fore.BLUE}Error fetching URL: {e}{Style.RESET_ALL}")
        return [], None

# Function to download the JavaScript file and save it locally
def download_js_file(js_url):
    try:
        response = requests.get(js_url)
        response.raise_for_status()
        filename = os.path.basename(urlparse(js_url).path)
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(response.text)
        return filename
    except requests.RequestException as e:
        print(f"{Fore.BLUE}Error downloading file: {e}{Style.RESET_ALL}")
        return None

# Function to search for sensitive information in JavaScript files
def search_sensitive_info(content):
    patterns = {
        'API Key': r'(?i)(api[-_]key|apikey|key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{20,})["\']?',
        'Token': r'(?i)(token)["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{20,})["\']?',
        'URL': r'(?i)(https?://[^\s\'";]+)',
        'Cookie': r'(?i)document\.cookie\s*=\s*["\']([^"\']+)["\']',
        'Link': r'(?i)href=["\'](https?://[^\s\'";]+)["\']',
        'Image': r'(?i)src=["\'](https?://[^\s\'";]+)["\']',
        'Form': r'(?i)<form[^>]*>(.*?)</form>',
    }

    results = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, content, re.DOTALL)
        if matches:
            results[key] = matches

    return results

# Function to extract data from HTML content
def extract_from_html(soup, extract_images, extract_forms):
    html_content = soup.prettify()  # Get the HTML content as a string

    results = {}
    if extract_images:
        images = re.findall(r'(?i)src=["\'](https?://[^\s\'";]+)["\']', html_content)
        if images:
            results['Image'] = images
    if extract_forms:
        forms = re.findall(r'(?i)<form[^>]*>(.*?)</form>', html_content, re.DOTALL)
        if forms:
            results['Form'] = forms

    return results

# Function to perform JS reconnaissance
def js_recon(target_url, extract_images=False, extract_api_keys=False, extract_forms=False):
    print(f"{Fore.BLUE}Starting JS Recon on {target_url}{Style.RESET_ALL}")

    js_files, soup = find_js_files(target_url)
    if not soup:
        return

    if extract_images or extract_forms:
        # Extract data from HTML if required
        html_data = extract_from_html(soup, extract_images, extract_forms)
        if html_data:
            print(f"{Fore.BLUE}HTML Data Extracted:{Style.RESET_ALL}")
            for data_type, data in html_data.items():
                print(f"{Fore.BLUE}{data_type}: {data}{Style.RESET_ALL}")

    for js_url in js_files:
        print(f"{Fore.BLUE}Processing: {js_url}{Style.RESET_ALL}")
        filename = download_js_file(js_url)
        if filename:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()

            sensitive_info = search_sensitive_info(content)

            if sensitive_info:
                print(f"{Fore.BLUE}Information Found in {filename}:{Style.RESET_ALL}")
                if extract_api_keys:
                    if 'API Key' in sensitive_info:
                        print(f"{Fore.BLUE}API Keys: {sensitive_info['API Key']}{Style.RESET_ALL}")
                if 'Image' in sensitive_info:
                    if extract_images:
                        print(f"{Fore.BLUE}Images: {sensitive_info['Image']}{Style.RESET_ALL}")
                if 'Form' in sensitive_info:
                    if extract_forms:
                        print(f"{Fore.BLUE}Forms: {sensitive_info['Form']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.BLUE}No relevant information found in {filename}.{Style.RESET_ALL}")
            print()
            os.remove(filename)  # Clean up the file

if __name__ == "__main__":
    # Print the banner
    print_banner()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Babruvahana: A tool for extracting sensitive information from JavaScript files and HTML content linked on a web page.'
    )
    parser.add_argument('url', type=str, help='The target URL to perform JS reconnaissance on.')
    parser.add_argument('--images', action='store_true', help='Extract images from the HTML content.')
    parser.add_argument('--api_keys', action='store_true', help='Extract API keys from JavaScript files.')
    parser.add_argument('--forms', action='store_true', help='Extract forms from the HTML content.')
    args = parser.parse_args()

    # Ensure URL starts with http or https
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.BLUE}Invalid URL format. Please include 'http://' or 'https://' at the beginning.{Style.RESET_ALL}")
    else:
        # Run the JS reconnaissance with specified extraction options
        js_recon(args.url, extract_images=args.images, extract_api_keys=args.api_keys, extract_forms=args.forms)
