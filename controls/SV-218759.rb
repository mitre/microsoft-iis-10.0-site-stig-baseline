control 'SV-218759' do
  title 'Directory Browsing on the IIS 10.0 website must be disabled.'
  desc 'Directory browsing allows the contents of a directory to be displayed upon request from a web client. If directory browsing is enabled for a directory in IIS, users could receive a web page listing the contents of the directory. If directory browsing is enabled the risk of inadvertently disclosing sensitive content is increased.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Click the Site.

Double-click the "Directory Browsing" icon.

If "Directory Browsing" is not installed, this is Not Applicable.

Under the "Actions" pane, verify "Directory Browsing" is "Disabled".

If "Directory Browsing" is not "Disabled", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the Site.

Double-click the "Directory Browsing" icon.

Under the "Actions" pane, click "Disabled".'
  impact 0.5
  tag check_id: 'C-20232r311175_chk'
  tag severity: 'medium'
  tag gid: 'V-218759'
  tag rid: 'SV-218759r879652_rule'
  tag stig_id: 'IIST-SI-000231'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-20230r311176_fix'
  tag 'documentable'
  tag legacy: ['SV-109343', 'V-100239']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_directory_browsing = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/directoryBrowse -name * | select -expand enabled').stdout.strip.split("\r\n")

  get_directory_browsing.zip(get_names).each do |directory_browsing, names|
    n = names.strip

    describe "The IIS site: #{n} websites enable directory browsing" do
      subject { directory_browsing }
      it { should cmp 'False' }
    end
  end

  if command('Get-WebConfiguration  system.webServer/globalModules/*').stdout.strip.include?('DirectoryListingModule')
    impact 0.0
    desc 'Directory Browsing is not installed, hence this control is Not Applicable.'
  end

  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
