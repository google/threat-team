rule MAL_G_APT_Backdoor_BRICKSTORM_3 {
   meta:
      description = "Detects BRICKSTORM backdoor used by APT group UNC5221 (China Nexus)"
      author = "Google Threat Intelligence Group (GTIG) (modified by Florian Roth)"
      date = "2025-09-25"
      score = 75
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign"
      md5 = "931eacd7e5250d29903924c31f41b7e5"
   strings:
      $str1 = { 48 8B 05 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 04 24 [0-5] E8 ?? ?? ?? ?? EB ?? }
      $str4 = "decompress" ascii
      $str5 = "MIMEHeader" ascii
      $str6 = "ResolveReference" ascii
      $str7 = "115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951" ascii
   condition:
      uint16(0) == 0x457F and all of them
}
