control 'V-36672' do
  title "Audit records must be backed up onto a different system or media than
  the system being audited."
  desc "Protection of log data includes assuring the log data is not
  accidentally lost or deleted.  Audit information stored in one location is
  vulnerable to accidental or incidental deletion or alteration."
  impact 0.5
  tag "gtitle": 'WINAU-000102'
  tag "gid": 'V-36672'
  tag "rid": 'SV-51566r2_rule'
  tag "stig_id": 'WN12-AU-000203-01'
  tag "fix_id": 'F-62923r1_fix'
  tag "cci": ['CCI-001851']
  tag "nist": ['AU-4 (1)', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine if a process to back up log data to a different
  system or media than the system being audited has been implemented.  If it has
  not, this is a finding."
  tag "fix": "Establish and implement a process for backing up log data to
  another system or media other than the system being audited."
  
  describe "Audit records must be backed up onto a different system or media than
  the system being audited" do
    skip 'is a manual check'
  end
end
