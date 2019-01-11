control "V-1165" do
  title "The computer account password must not be prevented from being reset."
  desc  "Computer account passwords are changed automatically on a regular
  basis.  Disabling automatic password changes can make the system more
  vulnerable to malicious access.  Frequent password changes can be a significant
  safeguard for your system.  A new password for the computer account will be
  generated every 30 days."
  impact 0.3
  tag "gtitle": "Computer Account Password Reset"
  tag "gid": "V-1165"
  tag "rid": "SV-52873r1_rule"
  tag "stig_id": "WN12-SO-000015"
  tag "fix_id": "F-45799r1_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24243-8']
  tag "nist": ['CM-6  b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: DisablePasswordChange

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
  member: Disable machine account password changes\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'DisablePasswordChange' }
    its('DisablePasswordChange') { should cmp == 0 }
  end
end

