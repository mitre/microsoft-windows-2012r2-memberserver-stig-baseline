control 'V-1128' do
  title "Security configuration tools or equivalent processes must be used to
  configure and maintain platforms for security compliance."
  desc "Security configuration tools such as Group Policies and Security
  Templates allow system administrators to consolidate security-related system
  settings into a single configuration file.  These settings can then be applied
  consistently to any number of Windows machines."
  impact 0.3
  tag "gtitle": 'Security Configuration Tools'
  tag "gid": 'V-1128'
  tag "rid": 'SV-52859r2_rule'
  tag "stig_id": 'WN12-00-000013'
  tag "fix_id": 'F-45785r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify security configuration tools or equivalent processes are
  being used to configure Windows systems to meet security requirements.  If
  security configuration tools or equivalent processes are not used, this is a
  finding.

  Security configuration tools that are integrated into Windows, such as Group
  Policies and Security Templates, may be used to configure platforms for
  security compliance.

  If an alternate method is used to configure a system (e.g., manually using the
  DISA Windows Security STIGs, etc.) and the same configured result is achieved,
  this is acceptable."
  tag "fix": "Implement a process using security configuration tools or the
  equivalent to configure Windows systems to meet security requirements."
  describe "A manual review is required to ensure security configuration tools or equivalent processes are used to
  configure and maintain platforms for security compliance" do
    skip 'A manual review is required to ensure security configuration tools or equivalent processes are used to
  configure and maintain platforms for security compliance'
  end
end
