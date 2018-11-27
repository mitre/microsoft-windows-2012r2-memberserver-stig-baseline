control 'V-26605' do
  title 'The Simple TCP/IP Services service must be disabled if installed.'
  desc  "Unnecessary services increase the attack surface of a system. Some of
  these services may not support required levels of authentication or encryption."
  impact 0.5
  tag "gtitle": 'Simple TCP/IP Services Disabled'
  tag "gid": 'V-26605'
  tag "rid": 'SV-52239r2_rule'
  tag "stig_id": 'WN12-SV-000104'
  tag "fix_id": 'F-45254r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-23748-7']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "Verify the Simple TCP/IP (simptcp) service is not installed or
  is disabled.

  Run \"Services.msc\".

  If the following is installed and not disabled, this is a finding:

  Simple TCP/IP Services (simptcp)"
  tag "fix": 'Remove or disable the Simple TCP/IP Services (simptcp) service.'
  describe.one do
    describe service('simptcp') do
      it { should_not be_installed }
    end
    describe service('simptcp') do
      it { should_not be_enabled }
    end
  end
end
