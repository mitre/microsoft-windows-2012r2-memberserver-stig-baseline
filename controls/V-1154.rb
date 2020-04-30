# frozen_string_literal: true

control 'V-1154' do
  title "The Ctrl+Alt+Del security attention sequence for logons must be
  enabled."
  desc "Disabling the Ctrl+Alt+Del security attention sequence can compromise
  system security.  Because only Windows responds to the Ctrl+Alt+Del security
  sequence, a user can be assured that any passwords entered following that
  sequence are sent only to Windows.  If the sequence requirement is eliminated,
  malicious programs can request and receive a user's Windows password.
  Disabling this sequence also suppresses a custom logon banner."
  impact 0.5
  tag "gtitle": 'Ctrl+Alt+Del Security Attention Sequence'
  tag "gid": 'V-1154'
  tag "rid": 'SV-52866r1_rule'
  tag "stig_id": 'WN12-SO-000019'
  tag "fix_id": 'F-45792r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25803-8']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: DisableCAD

  Value Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Interactive Logon: Do not require CTRL+ALT+DEL\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'DisableCAD' }
    its('DisableCAD') { should cmp == 0 }
  end
end
