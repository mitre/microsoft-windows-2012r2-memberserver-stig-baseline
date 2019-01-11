control "V-36670" do
  title "Audit data must be reviewed on a regular basis."
  desc  "To be of value, audit logs from critical systems must be reviewed on a
  regular basis.  Critical systems should be reviewed on a daily basis to
  identify security breaches and potential weaknesses in the security structure.
  This can be done with the use of monitoring software or other utilities for
  this purpose."
  impact 0.5
  tag "gtitle": "WINAU-000100"
  tag "gid": "V-36670"
  tag "rid": "SV-51561r1_rule"
  tag "stig_id": "WN12-AU-000200"
  tag "fix_id": "F-44692r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": "ECAT-1, ECAT-2"
  tag "check": "Determine whether audit logs are reviewed on a predetermined
  schedule.  If audit logs are not reviewed on a regular basis, this is a
  finding."
  tag "fix": "Review audit logs on a predetermined scheduled."
  describe 'A manual review is required to ensure audit data is reviewed on a regular basis' do
    skip 'A manual review is required to ensure audit data is reviewed on a regular basis'
  end
end

