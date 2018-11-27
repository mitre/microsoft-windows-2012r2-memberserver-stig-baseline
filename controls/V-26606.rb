control 'V-26606' do
  title 'The Telnet service must be disabled if installed.'
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": 'Telnet Service Disabled'
  tag "gid": 'V-26606'
  tag "rid": 'SV-52240r2_rule'
  tag "stig_id": 'WN12-SV-000105'
  tag "fix_id": 'F-45255r1_fix'
  tag "cci": ['CCI-000382']
  tag "cci": ['CCE-24474-9']
  tag "nist": ['CM-7 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "Verify the Telnet (tlntsvr) service is not installed or is
  disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Telnet (tlntsvr)"
  tag "fix": 'Remove or disable the Telnet (tlntsvr) service.'
  describe.one do
    describe service('tlntsvr') do
      it { should_not be_installed }
    end
    describe service('tlntsvr') do
      it { should_not be_enabled }
    end
  end
end
