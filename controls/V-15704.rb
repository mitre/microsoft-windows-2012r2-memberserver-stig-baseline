# frozen_string_literal: true

control 'V-15704' do
  title "Errors in handwriting recognition on tablet PCs must not be reported
  to Microsoft."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents errors in handwriting recognition on tablet PCs from
  being reported to Microsoft.
  "
  impact 0.3
  tag "gtitle": 'Handwriting Recognition Error Reporting'
  tag "gid": 'V-15704'
  tag "rid": 'SV-53116r1_rule'
  tag "stig_id": 'WN12-CC-000035'
  tag "fix_id": 'F-46042r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25580-2']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports\\

  Value Name: PreventHandwritingErrorReports

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication settings -> \"Turn off handwriting recognition error
  reporting\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports') do
    it { should have_property 'PreventHandwritingErrorReports' }
    its('PreventHandwritingErrorReports') { should cmp == 1 }
  end
end
