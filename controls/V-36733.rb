control 'V-36733' do
  title "User-level information must be backed up in accordance with local
  recovery time and recovery point objectives."
  desc "Operating system backup is a critical step in maintaining data
  assurance and availability.

  User-level information is data generated by information system and/or
  application users.

  Backups shall be consistent with organizational recovery time and recovery
  point objectives.
  "
  impact 0.3
  tag "gtitle": 'WINGE-000027'
  tag "gid": 'V-36733'
  tag "rid": 'SV-51581r2_rule'
  tag "stig_id": 'WN12-00-000015'
  tag "fix_id": 'F-63423r2_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Determine whether user-level information is backed up in
  accordance with local recovery time and recovery point objectives.  If
  user-level information is not backed up in accordance with local recovery time
  and recovery point objectives, this is a finding."
  tag "fix": "Implement user-level information backups in accordance with local
  recovery time and recovery point objectives."
  describe "A manual review is required to ensure user-level information is backed up in accordance with local
  recovery time and recovery point objectives." do
    skip 'A manual review is required to ensure user-level information is backed up in accordance with local
  recovery time and recovery point objectives.'
  end
end
