# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-22692' do
  title "The default Autorun behavior must be configured to prevent Autorun
  commands."
  desc "Allowing Autorun commands to execute may introduce malicious code to a
  system.  Configuring this setting prevents Autorun commands from executing."
  impact 0.7
  tag "gtitle": 'Default Autorun Behavior'
  tag "gid": 'V-22692'
  tag "rid": 'SV-53124r2_rule'
  tag "stig_id": 'WN12-CC-000073'
  tag "fix_id": 'F-46050r1_fix'
  tag "cci": ['CCI-001764']
  tag "cce": ['CCE-25487-0']
  tag "nist": ['CM-7 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

  Value Name: NoAutorun

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> AutoPlay Policies -> \"Set
  the default behavior for AutoRun\" to \"Enabled:Do not execute any autorun
  commands\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp == 1 }
  end
end
