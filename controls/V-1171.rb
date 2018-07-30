control "V-1171" do
  title "Ejection of removable NTFS media must be restricted to Administrators."
  desc  "Removable hard drives, if they are not properly configured, can be
  formatted and ejected by users who are not members of the Administrators Group.
   Formatting and ejecting removable NTFS media must only be done by
  administrators."
  impact 0.5
  tag "gtitle": "Format and Eject Removable Media"
  tag "gid": "V-1171"
  tag "rid": "SV-52875r1_rule"
  tag "stig_id": "WN12-SO-000011"
  tag "fix_id": "F-45801r1_fix"
  tag "cci": ["CCE-25217-1", "CCI-000366"]
  tag "nist": ["CCE-25217-1", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Value Name: AllocateDASD

  Value Type: REG_SZ
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Devices: Allowed to format and eject removable media\" to \"Administrators\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AllocateDASD" }
    its("AllocateDASD") { should cmp == 0 }
  end
end

