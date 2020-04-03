control 'V-3481' do
  title 'Media Player must be configured to prevent automatic Codec downloads.'
  desc  "The Windows Media Player uses software components, referred to as
  Codecs, to play back media files.  By default, when an unknown file type is
  opened with the Media Player, it will search the Internet for the appropriate
  Codec and automatically download it.  To ensure platform consistency and to
  protect against new vulnerabilities associated with media types, all Codecs
  must be installed by the System Administrator."
  impact 0.5
  tag "gtitle": 'Media Player - Prevent Codec Download'
  tag "gid": 'V-3481'
  tag "rid": 'SV-52921r1_rule'
  tag "stig_id": 'WN12-UC-000013'
  tag "fix_id": 'F-45847r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-23890-7']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

  Value Name: PreventCodecDownload

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Windows Components -> Windows Media Player ->
  Playback -> \"Prevent Codec Download\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsMediaPlayer') do
    it { should have_property 'PreventCodecDownload' }
    its('PreventCodecDownload') { should cmp == 1 }
  end
end
