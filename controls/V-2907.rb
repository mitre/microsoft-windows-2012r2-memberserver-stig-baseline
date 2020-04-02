control 'V-2907' do
  title 'System files must be monitored for unauthorized changes.'
  desc  "Monitoring system files for changes against a baseline on a regular
  basis may help detect the possible introduction of malicious code on a system."
  impact 0.5
  tag "gtitle": 'System File Changes'
  tag "gid": 'V-2907'
  tag "rid": 'SV-52215r2_rule'
  tag "stig_id": 'WN12-GE-000017'
  tag "fix_id": 'F-45234r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'DCSL-1'
  tag "check": "Determine whether the site monitors system files (e.g., *.exe,
  *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a
  baseline on a weekly basis.  If system files are not monitored for unauthorized
  changes, this is a finding.

  A properly configured HBSS Policy Auditor 5.2 or later File Integrity Monitor
  (FIM) module will meet the requirement for file integrity checking. The Asset
  module within HBSS does not meet this requirement."
  tag "fix": "Monitor system files (e.g., *.exe, *.bat, *.com, *.cmd, and
  *.dll) on servers for unauthorized changes against a baseline on a weekly
  basis.  This can be done with the use of various monitoring tools."
  
  describe 'A manual review is required to ensure system files are monitored for unauthorized changes' do
    skip 'A manual review is required to ensure system files are monitored for unauthorized changes'
  end
end
