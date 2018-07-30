control "V-57719" do
  title "The operating system must, at a minimum, off-load audit records of
  interconnected systems in real time and off-load standalone systems weekly."
  desc  "Protection of log data includes assuring the log data is not
  accidentally lost or deleted.  Audit information stored in one location is
  vulnerable to accidental or incidental deletion or alteration."
  impact 0.5
  tag "gtitle": "WINAU-000203"
  tag "gid": "V-57719"
  tag "rid": "SV-72133r1_rule"
  tag "stig_id": "WN12-AU-000203-02"
  tag "fix_id": "F-62925r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the operating system, at a minimum, off-loads audit
  records of interconnected systems in real time and off-loads standalone systems
  weekly.  If it does not, this is a finding."
  tag "fix": "Configure the operating system to, at a minimum, off-load audit
  records of interconnected systems in real time and off-load standalone systems
  weekly."
  describe "The operating system must, at a minimum, off-load audit records of
  interconnected systems in real time and off-load standalone systems weekly" do
    skip "is a manual check"
  end
end

