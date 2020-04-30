# frozen_string_literal: true

control 'V-36679' do
  title "Early Launch Antimalware, Boot-Start Driver Initialization Policy must
  be enabled and configured to only Good and Unknown."
  desc "Compromised boot drivers can introduce malware prior to some
  protection mechanisms that load after initialization.  The Early Launch
  Antimalware driver can limit allowed drivers based on classifications
  determined by the malware protection application.  At a minimum, drivers
  determined to be bad must not be allowed."
  impact 0.5
  tag "gtitle": 'WINCC-000027'
  tag "gid": 'V-36679'
  tag "rid": 'SV-51608r1_rule'
  tag "stig_id": 'WN12-CC-000027'
  tag "fix_id": 'F-44729r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25320-3']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECVP-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Policies\\EarlyLaunch\\

  Value Name: DriverLoadPolicy

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
Administrative Templates -> System -> Early Launch Antimalware -> \"Boot-Start
Driver Initialization Policy\" to \"Enabled\" with \"Good and Unknown\"
selected."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch') do
    it { should have_property 'DriverLoadPolicy' }
    its('DriverLoadPolicy') { should cmp == 1 }
  end
end
