control "V-36671" do
  title "Audit data must be retained for at least one year."
  desc  "Audit records are essential for investigating system activity after
  the fact.  Retention periods for audit data are determined based on the
  sensitivity of the data handled by the system."
  impact 0.5
  tag "gtitle": "WINAU-000101"
  tag "gid": "V-36671"
  tag "rid": "SV-51563r1_rule"
  tag "stig_id": "WN12-AU-000201"
  tag "fix_id": "F-44693r2_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECRR-1"
  tag "check": "Determine whether audit data is retained for at least one year.
  If the audit data is not retained for at least a year, this is a finding."
  tag "fix": "Ensure the audit data is retained for at least a year."
  describe "Audit data must be retained for at least one year" do
    skip "is a manual check"
  end
end

