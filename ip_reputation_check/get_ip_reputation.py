import sys
import ipaddress
import requests

"""
IT'S A SCRIPT, I'M NOT GOING TO PUT THE API KEYS IN A .ENV
"""
apikey_abuseipdb = ''
apikey_virustotal = ''
token_spamhaus = ''
BASE_SPAMHAUS_URL = "https://api.spamhaus.org/api"


def check_abuseipdb(ip_address: str) -> dict:
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90,
        'verbose': '',
    }
    headers = {
        'Key': apikey_abuseipdb,
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()  # Raise error for non-200 status codes

        response_json = response.json()
        if 'data' not in response_json:
            raise ValueError("Invalid response structure")

        attributes = response_json['data']
        
        isp = attributes.get('isp')
        country = attributes.get('countryName')
        totalReports = attributes.get('totalReports')
        numDistinctUsers = attributes.get('numDistinctUsers')
        usageType = attributes.get('usageType')
        domain = attributes.get('domain')
        abuseConfidenceScore = attributes.get('abuseConfidenceScore')

        return {
            'IP Address': ip_address,
            'Country': country,
            'ISP': isp,
            'Total No of Reports': totalReports,
            'Distinct Users': numDistinctUsers,
            'Usage Type': usageType,
            'Domain': domain,
            'Abuse Confidence Score': abuseConfidenceScore,
        }
    
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking IP {ip_address}: {e}")
        print("API rate limit per day might be completed.")
        return None
    
    except ValueError as e:
        print(f"Error parsing JSON response for IP {ip_address}: {e}")
        return None
    
    except Exception as e:
        print(f"An unexpected error occurred while processing IP {ip_address}: {e}")
        return None


def check_virustotal(ip_address: str, only_malicious: bool = True):
    """
    Devuelve la lista de motores (bases de datos) que analizan una IP en VirusTotal.
    
    Si only_malicious=True, devuelve solo los que detectan la IP como maliciosa.
    """

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers = {
        "Accept": "application/json",
        "x-apikey": apikey_virustotal
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Error API VirusTotal: {response.status_code} - {response.text}")

    data = response.json()

    analysis_results = data["data"]["attributes"]["last_analysis_results"]

    if only_malicious:
        return [
            engine
            for engine, result in analysis_results.items()
            if result.get("category") == "malicious"
        ]

    return list(analysis_results.keys())


def check_spamhaus( ip: str, dataset="SBL") -> bool:
    """
    Returns True if IP is listed in Spamhaus, False otherwise.
    """

    url = f"{BASE_SPAMHAUS_URL}/intel/v1/byobject/cidr/{dataset}/listed/live/{ip}"

    headers = {
        "Authorization": f"Bearer {token_spamhaus}"
    }

    resp = requests.get(url, headers=headers)

    # IP not listed
    if resp.status_code == 404:
        return False

    # Otros errores reales
    resp.raise_for_status()

    data = resp.json()
    
    # If returns a list (counts the enum)
    if isinstance(data, list):
        return len(data) > 0

    # Dict case
    if isinstance(data, dict):
        if "results" in data:
            return len(data["results"]) > 0
        return bool(data)

    return False


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ip_reputation(ip: str)-> list:
    
    output = dict()
    output["Abuseipdb"] = check_abuseipdb(ip)
    output["Virustotal"] = check_virustotal(ip)
    output["Spamhaus"] = check_spamhaus(ip)

    return output

if __name__ == "__main__":

    addr = sys.argv[1]
    if validate_ip(addr):
        print(get_ip_reputation(addr))
    else:
        print("Provide a correct ip addr")
