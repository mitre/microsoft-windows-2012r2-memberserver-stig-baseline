control "V-3385" do
  title "The system must be configured to require case insensitivity for
  non-Windows subsystems."
  desc  "This setting controls the behavior of non-Windows subsystems when
  dealing with the case of arguments or commands.  Case sensitivity could lead to
  the access of files or commands that must be restricted.  To prevent this from
  happening, case insensitivity restrictions must be required."
  impact 0.5
  tag "gtitle": "Case Insensitivity for Non-Windows"
  tag "gid": "V-3385"
  tag "rid": "SV-52897r1_rule"
  tag "stig_id": "WN12-SO-000075"
  tag "fix_id": "F-45823r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-24870-8"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\

  Value Name: ObCaseInsensitive

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"System
  objects: Require case insensitivity for non-Windows subsystems\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel") do
    it { should have_property "ObCaseInsensitive" }
    its("ObCaseInsensitive") { should cmp == 1 }
  end
end

