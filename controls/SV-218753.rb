control 'SV-218753' do
  title 'The IIS 10.0 website must be configured to limit the maxURL.'
  desc 'Request filtering replaces URLScan in IIS, enabling administrators to create a more granular rule set with which to allow or reject inbound web content. By setting limits on web requests, it helps to ensure availability of web services and may also help mitigate the risk of buffer overflow type attacks. The MaxURL Request Filter limits the number of bytes the server will accept in a URL.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click on the site name.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

If the "maxUrl" value is not set to "4096" or less, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Click the site name under review.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

Set the "maxURL" value to "4096" or less.'
  impact 0.5
  tag check_id: 'C-20226r311157_chk'
  tag severity: 'medium'
  tag gid: 'V-218753'
  tag rid: 'SV-218753r879650_rule'
  tag stig_id: 'IIST-SI-000225'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-20224r311158_fix'
  tag 'documentable'
  tag legacy: ['SV-109331', 'V-100227']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_maxurl = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/security/requestFiltering -name * | select -expand requestLimits | select -expand maxUrl').stdout.strip.split("\r\n")

  get_maxurl.zip(get_names).each do |maxurl, names|
    n = names.strip
    describe "IIS site: #{n} websites maxUrl" do
      subject { maxurl }
      it { should cmp <= 4096 }
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
