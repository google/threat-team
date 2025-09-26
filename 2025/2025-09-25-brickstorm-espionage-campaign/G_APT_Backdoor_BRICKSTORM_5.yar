rule G_Hunting_Backdoor_BRICKSTORM_2 {
   meta:
      author = "Google Threat Intelligence Group (GTIG)"
      date_created = "2025-08-19"
      md5 = "4645f2f6800bc654d5fa812237896b00"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
   strings:
      $ss_run_shell = { 48 B? 72 75 6E 5F 73 68 65 6C }
      $ss_run_1 = { 48 B? 52 75 6E 20 20 20 3E 3E [0-16] 48 B? 3E 3E 3E 3E 3E 3E 3E 3E [0-16] 48 B? 3E 3E 3E 3E 3E 3E 20 0A }
      $ss_run_2 = { 48 B? 52 75 6E 20 20 20 3E 3E 48 89 0? }
      $ss_exit_1 = { 48 B? 45 78 69 74 20 20 3E 3E [0-16] 48 B? 3E 3E 3E 3E 3E 3E 3E 3E [0-16] 48 B? 3E 3E 3E 3E 3E 3E 20 0A }
      $ss_exit_2 = { 48 B? 45 78 69 74 20 20 3E 3E 48 89 0? }
   condition:
      (
         uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550
         or uint32(0) == 0x464c457f
         or uint32(0) == 0xfeedface
         or uint32(0) == 0xcefaedfe
         or uint32(0) == 0xfeedfacf
         or uint32(0) == 0xcffaedfe
         or uint32(0) == 0xcafebabe
         or uint32(0) == 0xbebafeca
         or uint32(0) == 0xcafebabf
         or uint32(0) == 0xbfbafeca
      ) and 2 of them
}
