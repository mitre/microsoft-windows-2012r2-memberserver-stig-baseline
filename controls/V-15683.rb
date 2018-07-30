control "V-15683" do
  title "File Explorer shell protocol must run in protected mode."
  desc  "The shell protocol will  limit the set of folders applications can
  open when run in protected mode.  Restricting files an application can open to
  a limited set of folders increases the security of Windows."
  impact 0.5
  tag "gtitle": "Windows Explorer – Shell Protocol Protected Mode "
  tag "gid": "V-15683"
  tag "rid": "SV-53045r1_rule"
  tag "stig_id": "WN12-CC-000091"
  tag "fix_id": "F-45971r1_fix"
  tag "cci": ["CCE-23923-6", "CCI-000366"]
  tag "nist": ["CCE-23923-6", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

  Value Name: PreXPSP2ShellProtocolBehavior

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> File Explorer -> \"Turn off
  shell protocol protected mode\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "PreXPSP2ShellProtocolBehavior" }
    its("PreXPSP2ShellProtocolBehavior") { should cmp == 0 }
  end
end

