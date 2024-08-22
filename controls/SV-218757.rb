control 'SV-218757' do
  title 'Double encoded URL requests must be prohibited by any IIS 10.0 website.'
  desc 'Request filtering enables administrators to create a more granular rule set with which to allow or reject inbound web content. Setting limits on web requests ensures availability of web services and mitigates the risk of buffer overflow type attacks. When the "Allow double escaping" option is disabled, it prevents attacks that rely on double-encoded requests.'
  desc 'check', 'Note: If the server being reviewed is hosting SharePoint, this is Not Applicable.

Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

If the "Allow double escaping" check box is checked, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name under review.

Double-click the "Request Filtering" icon.

Click "Edit Feature Settings" in the "Actions" pane.

Uncheck the "Allow double escaping" check box.'
  impact 0.5
  tag check_id: 'C-20230r903118_chk'
  tag severity: 'medium'
  tag gid: 'V-218757'
  tag rid: 'SV-218757r903119_rule'
  tag stig_id: 'IIST-SI-000229'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-20228r311170_fix'
  tag 'documentable'
  tag legacy: ['SV-109339', 'V-100235']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_allowdouble_escaping = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/security/requestFiltering -name * | select -expand allowDoubleEscaping').stdout.strip.split("\r\n")

  get_allowdouble_escaping.zip(get_names).each do |allow_double_escaping, names|
    n = names.strip

    describe "The IIS site: #{n} websites Allow double escaping" do
      subject { allow_double_escaping }
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
