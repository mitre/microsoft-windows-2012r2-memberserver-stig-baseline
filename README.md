# microsoft-windows-2012r2-memberserver-stig-baseline

InSpec profile to validate the secure configuration of Microsoft Windows 2012 R2 Member Server, against [DISA](https://iase.disa.mil/stigs/)'s **Microsoft Windows Server 2012/2012 R2 Member Server Security Technical Implementation Guide (STIG) Version 2, Release 17**.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

### Please review and set these `inputs` as best fits your target

The profile _will_ run without updating these values but you will get the _best_ results if you provide the profile with the following data.

- sensitive_system (false) - set to either the string `"true"` or `"false"`
- domain_sid (NULL) - set to your Domain SID as a string in the form `xxxxxxxxxx-xxxxxxx-xxxxxxxxxx`
- backup_operators (NULL) - add your usernames as needed
- administrators (NULL) - add your usernames as needed
- hyper_v_admin (NULL) - add your usernames as needed
- av_approved_software(List of AV Software) - add your AV Software Product to this list
- shared_accounts (NULL) - add your usernames as needed
- local_administrator (NULL) - add your usernames as needed
- temp_accounts_domain (NULL) - add your usernames as needed
- temp_accounts_local (NULL) - add your usernames as needed
- emergency_accounts_domain (NULL) - add your usernames as needed
- emergency_accounts_local (NULL) - add your usernames as needed
- application_accounts_domain (NULL) - add your usernames as needed
- application_accounts_local (NULL) - add your usernames as needed
- excluded_accounts_domain (NULL) - add your usernames as needed
- application_services (NULL) - Need to allow for Control V-3487 to pass

### Domain Controller Controls are include in this Profile
    
    There are 7 Controls that Require the Profile be ran against a Domain controller. These Controls check for User Accounts that are on the domain and require restrictions. List below are these controls:

    - V-1112 - Outdated or unused accounts must be removed from the system or disabled.
    - V-6840 - Windows 2012/2012 R2 passwords must be configured to expire.
    - V-7002 - Windows 2012/2012 R2 accounts must be configured to require passwords.
    - V-14225 - Windows 2012/2012 R2 password for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.
    - V-36662 - Windows 2012/2012 R2 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.
    - V-57653 - If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.
    - V-57655 - Emergency administrator accounts are privileged accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

## Running This Profile

    inspec exec https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline/archive/master.tar.gz -t winrm://<hostip> --user '<admin-account>' --password=<password> --reporter cli json:<filename>.json

Runs this profile over __winrm__ to the host at IP address __hostip__ as a privileged user account (i.e., an account with administrative privileges), reporting results to both the command line interface (cli) and to a machine-readable JSON file. 
    
The following is an example of using this command. 

    inspec exec https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline/archive/master.tar.gz -t winrm://$winhostip --user 'Administrator' --password=Pa55w0rd --reporter cli json:windows-memberserver-results.json

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __full heimdall server__, allowing for additional functionality such as to store and compare multiple profile runs.

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline/issues/new).

For other help, please send a message to [inspec@mitre.org](mailto:inspec@mitre.org).

To contribute, please review the [contribution guidelines](https://github.com/mitre/docs-mitre-inspec/blob/master/CONTRIBUTING.md).

## Authors
- Alicia Sturtevant
- Jared Burns

## Special Thanks

- The MITRE InSpec Team

## License 

This project is licensed under the terms of the [Apache 2.0 license](https://github.com/mitre/microsoft-windows-2012r2-memberserver-stig-baseline/blob/master/LICENSE.md).

### NOTICE

© 2019 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx   
