control 'V-1074' do
  title 'The Windows 2012 / 2012 R2 system must use an anti-virus program.'
  desc  "Malicious software can establish a base on individual desktops and
  servers. Employing an automated mechanism to detect this type of software will
  aid in elimination of the software from the operating system."
  impact 0.7
  tag "gtitle": 'WIN00-000100'
  tag "gid": 'V-1074'
  tag "rid": 'SV-52103r4_rule'
  tag "stig_id": 'WN12-00-000100'
  tag "fix_id": 'F-82943r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Verify an anti-virus solution is installed on the system. The
  anti-virus solution may be bundled with an approved host-based security
  solution.

  If there is no anti-virus solution installed on the system, this is a finding."
  tag "fix": 'he Windows 2012 / 2012 R2 system must use an anti-virus program'
  describe.one do
    describe registry_key('HKLM\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion') do
      it { should exist }
    end
    describe registry_key('HKLM\SOFTWARE\McAfee/DesktopProtection\szProductVer') do
      it { should exist }
    end
    describe registry_key('HKLM\SOFTWARE\McAfee\Endpoint\AV\ProductVersion') do
      it { should exist }
    end
  end
end
