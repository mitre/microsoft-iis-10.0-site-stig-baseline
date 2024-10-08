control 'SV-218758' do
  title 'Unlisted file extensions in URL requests must be filtered by any IIS 10.0 website.'
  desc 'Request filtering enables administrators to create a more granular rule set to allow or reject inbound web content. Setting limits on web requests helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks. The allow unlisted property of the "File Extensions Request" filter enables rejection of requests containing specific file extensions not defined in the "File Extensions" filter. Tripping this filter will cause IIS to generate a Status Code 404.7.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

If the "Allow unlisted file name extensions" check box is checked, this is a finding.

Note: If this IIS 10.0 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Note: If this IIS 10.0 installation is supporting Splunk, this requirement is Not Applicable.

Note: If this IIS 10.0 installation is supporting WSUS, this requirement is Not Applicable.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

Uncheck the "Allow unlisted file extensions" check box.'
  impact 0.5
  tag check_id: 'C-20231r903120_chk'
  tag severity: 'medium'
  tag gid: 'V-218758'
  tag rid: 'SV-218758r903121_rule'
  tag stig_id: 'IIST-SI-000230'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-20229r311173_fix'
  tag 'documentable'
  tag legacy: ['SV-109341', 'V-100237']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_allow_unlisted = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/security/requestFiltering -name * | select -expand fileExtensions | select -expand allowUnlisted').stdout.strip.split("\r\n")

  get_allow_unlisted.zip(get_names).each do |allow_unlisted, names|
    n = names.strip

    describe "The IIS site: #{n} websites Allow unlisted file extension" do
      subject { allow_unlisted }
      it { should cmp 'False' }
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
