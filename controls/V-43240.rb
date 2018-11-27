control 'V-43240' do
  title "The network selection user interface (UI) must not be displayed on the
  logon screen (Windows 2012 R2)."
  desc  "Enabling interaction with the network selection UI allows users to
  change connections to available networks without signing into Windows."
  impact 0.5
  tag "gtitle": 'WINCC-000140'
  tag "gid": 'V-43240'
  tag "rid": 'SV-56346r2_rule'
  tag "stig_id": 'WN12-CC-000140'
  tag "fix_id": 'F-49192r2_fix'
  tag "cci": ['CCI-000381']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "This requirement is NA for the initial release of Windows 2012.
   It is applicable to Windows 2012 R2.

  Verify the registry value below.  If it does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

  Value Name: DontDisplayNetworkSelectionUI

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "This requirement is NA for the initial release of Windows 2012.
  It is applicable to Windows 2012 R2.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> System -> Logon -> \"Do not display network selection UI\" to
  \"Enabled\"."
  if os['release'].to_i < 6.3
    impact 0.0
    describe 'System is not Windows 2012, control is NA' do
      skip 'System is not Windows 2012, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System') do
      it { should have_property 'DontDisplayNetworkSelectionUI' }
      its('DontDisplayNetworkSelectionUI') { should cmp == 1 }
    end
  end
end
