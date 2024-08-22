control 'SV-218750' do
  title 'Anonymous IIS 10.0 website access accounts must be restricted.'
  desc 'Many of the security problems that occur are not the result of a user gaining access to files or data for which the user does not have permissions, but rather users are assigned incorrect permissions to unauthorized data. The files, directories, and data stored on the web server must be evaluated and a determination made concerning authorized access to information and programs on the server. Only authorized users and administrative accounts will be allowed on the host server in order to maintain the web server, applications, and review the server operations.'
  desc 'check', 'Check the account used for anonymous access to the website.

Follow the procedures below for each site hosted on the IIS 10.0 web server:
Open the IIS 10.0 Manager.

Double-click "Authentication" in the IIS section of the website’s Home Pane.

If "Anonymous access" is disabled, this is Not a Finding.

If "Anonymous access" is enabled, click "Anonymous Authentication".

Click "Edit" in the "Actions" pane.

If the "Specific user" radio button is enabled and an ID is specified in the adjacent control box, this is the ID being used for anonymous access. Note the account name.

If nothing is tied to "Specific User", this is Not a Finding.

Check privileged groups that may allow the anonymous account inappropriate membership:
Open "Computer Management" on the machine.

Expand "Local Users and Groups".

Open "Groups".

Review the members of any of the following privileged groups:

Administrators
Backup Operators
Certificate Services (of any designation)
Distributed COM Users
Event Log Readers
Network Configuration Operators
Performance Log Users
Performance Monitor Users
Power Users
Print Operators
Remote Desktop Users
Replicator

Double-click each group and review its members.

If the IUSR account or any account noted above used for anonymous access is a member of any group with privileged access, this is a finding.'
  desc 'fix', 'Remove the Anonymous access account from all privileged accounts and all privileged groups.'
  impact 0.7
  tag check_id: 'C-20223r928847_chk'
  tag severity: 'high'
  tag gid: 'V-218750'
  tag rid: 'SV-218750r928848_rule'
  tag stig_id: 'IIST-SI-000221'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-20221r311149_fix'
  tag 'documentable'
  tag legacy: ['SV-109325', 'V-100221']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  get_names = command("Get-Website | select name | findstr /r /v '^$' | findstr /v 'name ---'").stdout.strip.split("\r\n")

  get_names.each do |names|
    n = names.strip

    is_anonymous_access_enabled = command("Get-WebConfigurationProperty -pspath \"IIS:\Sites\\#{n}\" -filter system.webServer/security/authentication/anonymousAuthentication -name * | select -expand Enabled").stdout.strip.split("\n")

    is_anonymous_access_enabled.each do |a|
      if a == 'True'
        get_anonymous_authentication_account = command("Get-WebConfigurationProperty -pspath \"IIS:\Sites\\#{n}\" -Filter system.webServer/security/authentication/anonymousAuthentication -name * | select -expand userName").stdout.strip

        describe "Users allowed anonymous access in the Administrator group for IIS site #{n}" do
          subject { command("net localgroup Administrators | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Backup Operators group for IIS site #{n}" do
          subject { command("net localgroup 'Backup Operators' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Certificate Service DCOM Access group for IIS site #{n}" do
          subject { command("net localgroup 'Certificate Service DCOM Access' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Distributed COM Users group for IIS site #{n}" do
          subject { command("net localgroup 'Distributed COM Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Event Log Readers group for IIS site #{n}" do
          subject { command("net localgroup 'Event Log Readers' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Network Configuration Operators group for IIS site #{n}" do
          subject { command("net localgroup 'Network Configuration Operators' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Performance Log Users group for IIS site #{n}" do
          subject { command("net localgroup 'Performance Log Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Performance Monitor Users group for IIS site #{n}" do
          subject { command("net localgroup 'Performance Monitor Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Power Users group for IIS site #{n}" do
          subject { command("net localgroup 'Power Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Print Operators group for IIS site #{n}" do
          subject { command("net localgroup 'Print Operators' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Remote Desktop Users group for IIS site #{n}" do
          subject { command("net localgroup 'Remote Desktop Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Replicator group for IIS site #{n}" do
          subject { command("net localgroup 'Replicator' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end

        describe "Users allowed anonymous access in the Users group for IIS site #{n}" do
          subject { command("net localgroup 'Users' | Findstr #{get_anonymous_authentication_account}").stdout }
          it { should eq '' }
        end
      else
        describe "IIS site #{n} anonymous access setting" do
          subject { a }
          it { should cmp 'False' }
        end
      end
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
