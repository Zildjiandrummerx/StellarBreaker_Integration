import hashlib, hmac, base64, json, urllib.request, requests, re, os, yaml
from urllib.parse import urlencode
requests.packages.urllib3.disable_warnings()

API_KEY = 'XXXX'
SHARED_KEY = 'XXXX'

endpoint = 'https://api.silobreaker.com/v1/heat'
query = '(provider:"intel471*" OR provider:"flashpoint*" OR provider:"Mandiant*") AND doctype:"Report" AND entitytype:"IPv4" AND fromdate:"-7"'

# Preparing the body to match the query:
body = {
    "q": query,
    "tq": "entitytype:\"IPv4\""
}

# Building the URL and encoding it (Required by the API. Check documentation)
bodyEncoder = urlencode(body)
url = endpoint + '?' + bodyEncoder
message = f'GET {url}'
print(f'\nSilobreaker API Call: \n{message}')

# Calculating the digest
hmac_sha1 = hmac.new(SHARED_KEY.encode(), message.encode(), digestmod=hashlib.sha1)
digest = base64.b64encode(hmac_sha1.digest())
print(f'\nApplying Digest: {digest}')

# Preparing the final URL and sending the GET request to fetch the data
final_url = url + "&apiKey=" + API_KEY + "&digest=" + urllib.parse.quote(digest.decode())
req = urllib.request.Request(final_url)
print(f'\nFinal URL + Query + Digest:\n{final_url}')

with urllib.request.urlopen(req) as response:
    responseJson = response.read()

# Pretty print the data for troubleshooting purposes (Uncomment line below)
responseObject = json.loads(responseJson.decode("utf-8"))
#print(json.dumps(responseObject, sort_keys=True, indent=2, separators=(',', ': ')))

# Extract the IP addresses
ip_addresses = set()
for item in responseObject['Items']:
    description = item['Description']
    # Extracting IP addresses from the description field
    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', description)
    ip_addresses.update(ips)

# Load false positives from JSON file
false_positives = []
if os.path.exists('falsePositive.json'):
    with open('falsePositive.json', 'r') as fp_file:
        false_positives = json.load(fp_file)

# Filter out false positives from the extracted IP addresses
filtered_ips = [ip for ip in ip_addresses if ip not in false_positives]

# Writing unique IP addresses to the text file
new_ips = []
if os.path.exists('master_file.txt'):
    with open('master_file.txt', 'r') as file:
        existing_ips = set(file.read().splitlines())
    new_ips = list(ip_addresses - existing_ips)

if new_ips:
    with open('master_file.txt', 'a') as file:
        file.write("\n".join(new_ips) + "\n")
        print(f"\nAppended {len(new_ips)} new IP addresses to master_file.txt.")
else:
    if not os.path.exists('master_file.txt'):
        with open('master_file.txt', 'w') as file:
            file.write("\n".join(ip_addresses) + "\n")
            print("master_file.txt created with all extracted IP addresses.")
    else:
        print("\nNo new IP addresses found.")

##################################################################################
#  Code below is for uploading all loggued IPs into a StellarCyber LookUp Group
##################################################################################

# Read StellarCyber's API token from YAML file
with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)
    api_token = config['api_token']
    port = config['listen_port']

ip_address = '141.148.135.159'
endpoint = f'https://{ip_address}:{port}/stellarlookups'

# Defining all header params
headers = {
    'Content-Type': 'application/json',
    'Stellar-Token': api_token
}

# Read IP addresses from master_file.txt
with open('master_file.txt', 'r') as file:
    ip_addresses = file.read().splitlines()

# Send each IP address to the endpoint one by one
for ip in ip_addresses:
    # Prepare the data payload for the POST request
    data = {
        "name": "Silobreaker Ransomware IPs Last 14 Days",
        "add": ip
    }

    response_post = requests.post(endpoint, headers=headers, verify=False, json=data)
    print(f'POST Request URL: {response_post.request.url}\n')
    print(f'Headers: {response_post.request.headers}\n')
    print(f'Payload: {response_post.request.body}\n')
    print(f'Status Code: {response_post.status_code}.\n')
    print(f'POST Response: \n{response_post.text}\n\n')

    # Checking for status response errors
    if response_post.status_code != 200:
        print(f'Status Error Message: {response_post.text}\n\n')
