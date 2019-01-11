control "V-36711" do
  title "The Windows Store application must be turned off."
  desc  "Uncontrolled installation of applications can introduce various
  issues, including system instability, and provide access to sensitive
  information.  Installation of applications must be controlled by the
  enterprise.  Turning off access to the Windows Store will limit access to
  publicly available applications."
  impact 0.5
  tag "gtitle": "WINCC-000110"
  tag "gid": "V-36711"
  tag "rid": "SV-51751r2_rule"
  tag "stig_id": "WN12-CC-000110"
  tag "fix_id": "F-62333r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "The Windows Store is not installed by default. If the
  \\Windows\\WinStore directory does not exist, this is NA.
  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\

  Value Name:  RemoveWindowsStore

  Type:  REG_DWORD
  Value:  1"
  tag "fix": "The Windows Store is not installed by default.  If the
  \\Windows\\WinStore directory does not exist, this is NA.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Windows Components -> Store -> \"Turn off the Store application\"
  to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore') do
    it { should have_property 'RemoveWindowsStore' }
    its('RemoveWindowsStore') { should cmp == 1 }
  end if registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?

  if !registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore').exists?
    impact 0.0
    describe 'The system does not have Windows Store installed' do
      skip "The system does not have Windows Store installed, this requirement is Not
      Applicable."
    end
  end
end

