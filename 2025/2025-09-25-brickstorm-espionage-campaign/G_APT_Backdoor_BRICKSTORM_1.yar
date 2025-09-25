rule MAL_G_APT_Backdoor_BRICKSTORM_1 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      md5 = "4645f2f6800bc654d5fa812237896b00"
   strings:
      $ = "WRITE_LOGWednesday"
      $ = "/home/vsphere-ui/"
      $ = "WRITE_LOG=true"
      $ = "dns rcode: %v"
      $ = "/libs/doh.createDnsMessage"
      $ = "/libs/func1.(*Client).BackgroundRun"
      $ = "/libs/func1.CreateClient"
      $ = "/core/extends/command.CommandNoContext"
      $ = "/core/extends/command.ExecuteCmd"
      $ = "/core/extends/command.RunShell"
      $ = "/libs/fs.(*RemoteDriver).DeleteFile"
      $ = "/libs/fs.(*RemoteDriver).GetFile"
      $ = "/libs/fs.(*RemoteDriver).PutFile"
      $ = "/libs/doh/doh.go"
   condition:
      uint32(0) == 0x464c457f and 5 of them
      or 8 of them  // allow for in-memory detection
}
