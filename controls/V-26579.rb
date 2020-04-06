control 'V-26579' do
  title "The Application event log size must be configured to 32768 KB or
  greater."
  desc "Inadequate log size will cause the log to fill up quickly. This may
  prevent audit events from being recorded properly and require frequent
  attention by administrative personnel."
  impact 0.5
  tag "gtitle": 'Maximum Log Size - Application'
  tag "gid": 'V-26579'
  tag "rid": 'SV-52966r2_rule'
  tag "stig_id": 'WN12-CC-000084'
  tag "fix_id": 'F-71601r2_fix'
  tag "cci": ['CCI-001849']
  tag "cce": ['CCE-24277-6']
  tag "nist": ['AU-4', 'Rev_4']
  tag "documentable": false
  tag "check": "If the system is configured to write events directly to an
  audit server, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application\\

  Value Name: MaxSize

  Type: REG_DWORD
  Value: 0x00008000 (32768) (or greater)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> Event Log Service >>
  Application >> \"Specify the maximum log file size (KB)\" to \"Enabled\" with a
  \"Maximum Log Size (KB)\" of \"32768\" or greater."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application') do
    it { should have_property 'MaxSize' }
    its('MaxSize') { should cmp >= 32768 }
  end
end
