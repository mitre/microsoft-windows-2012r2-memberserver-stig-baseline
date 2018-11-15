control "V-1174" do
  title "The amount of idle time required before suspending a session must be
  properly set."
  desc  "Open sessions can increase the avenues of attack on a system.  This
  setting is used to control when a computer disconnects an inactive SMB session.
  If client activity resumes, the session is automatically reestablished.  This
  protects critical and sensitive network data from exposure to unauthorized
  personnel with physical access to the computer."
  impact 0.3
  tag "gtitle": "Idle Time Before Suspending a Session."
  tag "gid": "V-1174"
  tag "rid": "SV-52878r3_rule"
  tag "stig_id": "WN12-SO-000031"
  tag "fix_id": "F-45804r2_fix"
  tag "cci": ["CCI-002361"]
  tag "cce": ["CCE-23897-2"]
  tag "nist": ["AC-12", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:
  \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name:  autodisconnect

  Value Type:  REG_DWORD
  Value:  0x0000000f (15) (or less)"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Microsoft Network Server: Amount of idle time required before suspending
  session\" to \"15\" minutes or less."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters") do
    it { should have_property "AutoDisconnect" }
    its("AutoDisconnect") { should cmp <= 15 }
  end
end

