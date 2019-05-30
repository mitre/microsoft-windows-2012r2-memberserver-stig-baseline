control 'V-32282' do
  title "Standard user accounts must only have Read permissions to the Active
  Setup\\Installed Components registry key."
  desc "Permissions on the Active Setup\\Installed Components registry key
  must only allow privileged accounts to add or change registry values.  If
  standard user accounts have these permissions, there is a potential for
  programs to run with elevated privileges when a privileged user logs on to the
  system."
  impact 0.7
  tag "gtitle": "WINRG-000001 Active Setup\\Installed Components Registry
  Permissions"
  tag "gid": 'V-32282'
  tag "rid": 'SV-52956r3_rule'
  tag "stig_id": 'WN12-RG-000002'
  tag "fix_id": 'F-71731r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Run \"Regedit\".
  Navigate to the following registry keys and review the permissions:
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed
  Components\\ (64-bit systems)

  If the default permissions listed below have been changed, this is a finding.

  Users - Read
  Administrators - Full Control
  SYSTEM - Full Control
  CREATOR OWNER - Full Control (Subkeys only)
  ALL APPLICATION PACKAGES - Read"
  tag "fix": "Maintain the default permissions of the following registry keys:
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed
  Components\\ (64-bit systems only)

  Users - Read
  Administrators - Full Control
  SYSTEM - Full Control
  CREATOR OWNER - Full Control (Subkeys only)
  ALL APPLICATION PACKAGES - Read"

  describe windows_registry("HKLM:\\Software\\Microsoft\\Active Setup\\Installed Components\\") do
    it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
    it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
    it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
    it { should be_allowed('full-control', by_user: 'NT SERVICE\\TrustedInstaller') }
    it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
  end

   describe windows_registry("HKLM:\\Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\") do
    it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
    it { should be_allowed('read', by_user: 'BUILTIN\\Users') }
    it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('full-control', by_user: 'CREATOR OWNER') }
    it { should be_allowed('read', by_user: 'APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES') }
  end

end



