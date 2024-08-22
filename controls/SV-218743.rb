control 'SV-218743' do
  title 'The IIS 10.0 website must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or could use the function in an unintentional manner.

A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server."
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click on the IIS 10.0 site.

Under IIS, double-click the “MIME Types” icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", verify MIME types for OS shell program extensions have been removed, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

If any OS shell MIME types are configured, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click on the IIS 10.0 site.

Under IIS, double-click the “MIME Types” icon.

From the "Group by:" drop-down list, select "Content Type".

From the list of extensions under "Application", remove MIME types for OS shell program extensions, to include at a minimum, the following extensions:

.exe
.dll
.com
.bat
.csh

Select "Apply" from the "Actions" pane.'
  impact 0.5
  tag check_id: 'C-20216r311127_chk'
  tag severity: 'medium'
  tag gid: 'V-218743'
  tag rid: 'SV-218743r879587_rule'
  tag stig_id: 'IIST-SI-000214'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-20214r311128_fix'
  tag 'documentable'
  tag legacy: ['SV-109311', 'V-100207']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  get_names = command("Get-Website | select name | findstr /r /v '^$' | findstr /v 'name ---'").stdout.strip.split("\r\n")

  get_names.each do |names|
    n = names.strip
    exe_files = command("Get-WebConfiguration -pspath \"IIS:\Sites\\#{n}\" -filter \"system.webServer/staticContent/mimeMap\" | ? {$_.fileextension -eq '.exe'}").stdout
    dll_files = command("Get-WebConfiguration -pspath \"IIS:\Sites\\#{n}\" -filter \"system.webServer/staticContent/mimeMap\" | ? {$_.fileextension -eq '.dll'}").stdout

    com_files = command("Get-WebConfiguration -pspath \"IIS:\Sites\\#{n}\" -filter \"system.webServer/staticContent/mimeMap\" | ? {$_.fileextension -eq '.com'}").stdout

    bat_files = command("Get-WebConfiguration -pspath \"IIS:\Sites\\#{n}\" -filter \"system.webServer/staticContent/mimeMap\" | ? {$_.fileextension -eq '.bat'}").stdout

    csh_files = command("Get-WebConfiguration -pspath \"IIS:\Sites\\#{n}\" -filter \"system.webServer/staticContent/mimeMap\" | ? {$_.fileextension -eq '.csh'}").stdout

    describe "The IIS Site: #{n} MIME .exe files found" do
      subject { exe_files }
      it { should be_empty }
    end
    describe "The IIS Site: #{n}  MIME .dll files found" do
      subject { dll_files }
      it { should be_empty }
    end
    describe "The IIS Site: #{n} MIME .com files found" do
      subject { com_files }
      it { should be_empty }
    end
    describe "The IIS Site: #{n} .bat files found" do
      subject { bat_files }
      it { should be_empty }
    end
    describe "The IIS Site: #{n} MIME .csh files found" do
      subject { csh_files }
      it { should be_empty }
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
