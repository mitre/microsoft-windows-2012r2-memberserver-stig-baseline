
control 'V-1089' do
  title "The required legal notice must be configured to display before console
  logon."
  desc  "Failure to display the logon banner prior to a logon attempt will
  negate legal proceedings resulting from unauthorized access to system
  resources."
  impact 0.5
  tag "gtitle": 'Legal Notice Display'
  tag "gid": 'V-1089'
  tag "rid": 'SV-52845r3_rule'
  tag "stig_id": 'WN12-SO-000022'
  tag "fix_id": 'F-45771r3_fix'
  tag "cci": ['CCE-25355-9', 'CCI-000048', 'CCI-000050', 'CCI-001384',
              'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag "nist": ['AC-8 a', 'Rev_4']
  tag "nist": ['AC-8 b', 'Rev_4']
  tag "nist": ['AC-8 c 1', 'Rev_4']
  tag "nist": ['AC-8 c 2', 'Rev_4']
  tag "nist": ['AC-8 c 3', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: LegalNoticeText

  Value Type: REG_SZ
  Value: See message text below

  You are accessing a U.S. Government (USG) Information System (IS) that is
  provided for USG-authorized use only.

  By using this IS (which includes any device attached to this IS), you consent
  to the following conditions:

  -The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC monitoring,
  network operations and defense, personnel misconduct (PM), law enforcement
  (LE), and counterintelligence (CI) investigations.

  -At any time, the USG may inspect and seize data stored on this IS.

  -Communications using, or data stored on, this IS are not private, are subject
  to routine monitoring, interception, and search, and may be disclosed or used
  for any USG-authorized purpose.

  -This IS includes security measures (e.g., authentication and access controls)
  to protect USG interests--not for your personal benefit or privacy.

  -Notwithstanding the above, using this IS does not constitute consent to PM, LE
  or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or services
  by attorneys, psychotherapists, or clergy, and their assistants.  Such
  communications and work product are private and confidential.  See User
  Agreement for details."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >>
  \"Interactive Logon: Message text for users attempting to log on\" to the
  following:

  You are accessing a U.S. Government (USG) Information System (IS) that is
  provided for USG-authorized use only.

  By using this IS (which includes any device attached to this IS), you consent
  to the following conditions:

  -The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC monitoring,
  network operations and defense, personnel misconduct (PM), law enforcement
  (LE), and counterintelligence (CI) investigations.

  -At any time, the USG may inspect and seize data stored on this IS.

  -Communications using, or data stored on, this IS are not private, are subject
  to routine monitoring, interception, and search, and may be disclosed or used
  for any USG-authorized purpose.

  -This IS includes security measures (e.g., authentication and access controls)
  to protect USG interests--not for your personal benefit or privacy.

  -Notwithstanding the above, using this IS does not constitute consent to PM, LE
  or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or services
  by attorneys, psychotherapists, or clergy, and their assistants.  Such
  communications and work product are private and confidential.  See User
  Agreement for details."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'LegalNoticeText' }
  end

  key = registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').LegalNoticeText.to_s

  k = key.gsub("\u0000", '')
  legal_notice_text = attribute('LegalNoticeText')

  describe 'The required legal notice text' do
    subject { k.scan(/[\w().;,!]/).join }
    it {should cmp legal_notice_text.scan(/[\w().;,!]/).join }
  end
end
