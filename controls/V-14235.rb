control "V-14235" do
  title "User Account Control must, at minimum, prompt administrators for
  consent."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting configures the elevation requirements for logged on administrators
  to complete a task that requires raised privileges."
  impact 0.5
  tag "gtitle": "UAC - Admin Elevation Prompt"
  tag "gid": "V-14235"
  tag "rid": "SV-52947r1_rule"
  tag "stig_id": "WN12-SO-000078"
  tag "fix_id": "F-45873r2_fix"
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-23877-4']
  tag "nist": ['SC-3', 'Rev_4']
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
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: ConsentPromptBehaviorAdmin

  Value Type: REG_DWORD
  Value: 4 (Prompt for consent)
  3 (Prompt for credentials)
  2 (Prompt for consent on the secure desktop)
  1 (Prompt for credentials on the secure desktop)"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Behavior of the elevation prompt for administrators in Admin Approval
  Mode\" to \"Prompt for consent\".

  More secure options for this setting would also be acceptable (e.g., Prompt for
  credentials, Prompt for consent (or credentials) on the secure desktop)."
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'ConsentPromptBehaviorAdmin' }
      its('ConsentPromptBehaviorAdmin') { should cmp <= 4 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'ConsentPromptBehaviorAdmin' }
      its('ConsentPromptBehaviorAdmin') { should cmp > 0 }
    end
  end
end

