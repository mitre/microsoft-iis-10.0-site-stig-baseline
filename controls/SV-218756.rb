control 'SV-218756' do
  title 'Non-ASCII characters in URLs must be prohibited by any IIS 10.0 website.'
  desc 'Setting limits on web requests ensures availability of web services and mitigates the risk of buffer overflow type attacks. The allow high-bit characters Request Filter enables rejection of requests containing non-ASCII characters.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

If the "Allow high-bit characters" check box is checked, this is a finding.

Note: If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

Uncheck the "Allow high-bit characters" check box.'
  impact 0.5
  tag check_id: 'C-20229r311166_chk'
  tag severity: 'medium'
  tag gid: 'V-218756'
  tag rid: 'SV-218756r879650_rule'
  tag stig_id: 'IIST-SI-000228'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-20227r311167_fix'
  tag 'documentable'
  tag legacy: ['SV-109337', 'V-100233']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_allowHighBitCharacters = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/security/requestFiltering -name * | select -expand allowHighBitCharacters').stdout.strip.split("\r\n")

  get_allowHighBitCharacters.zip(get_names).each do |allowHighBitCharacters, names|
    n = names.strip

    describe "The IIS site: #{n} websites Allow high-bit characters" do
      subject { allowHighBitCharacters }
      it { should cmp 'True' }
    end
  end
  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end
end
