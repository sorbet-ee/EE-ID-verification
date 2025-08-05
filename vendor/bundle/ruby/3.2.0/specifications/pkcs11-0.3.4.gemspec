# -*- encoding: utf-8 -*-
# stub: pkcs11 0.3.4 ruby lib
# stub: ext/extconf.rb

Gem::Specification.new do |s|
  s.name = "pkcs11".freeze
  s.version = "0.3.4".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "homepage_uri" => "http://github.com/larskanis/pkcs11" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Ryosuke Kutsuna".freeze, "GOTOU Yuuzou".freeze, "Lars Kanis".freeze]
  s.cert_chain = ["-----BEGIN CERTIFICATE-----\nMIIDLjCCAhagAwIBAgIBCjANBgkqhkiG9w0BAQsFADA9MQ4wDAYDVQQDDAVrYW5p\nczEXMBUGCgmSJomT8ixkARkWB2NvbWNhcmQxEjAQBgoJkiaJk/IsZAEZFgJkZTAe\nFw0yMjA0MTExMTMwNTNaFw0yMzA0MTExMTMwNTNaMD0xDjAMBgNVBAMMBWthbmlz\nMRcwFQYKCZImiZPyLGQBGRYHY29tY2FyZDESMBAGCgmSJomT8ixkARkWAmRlMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApop+rNmg35bzRugZ21VMGqI6\nHGzPLO4VHYncWn/xmgPU/ZMcZdfj6MzIaZJ/czXyt4eHpBk1r8QOV3gBXnRXEjVW\n9xi+EdVOkTV2/AVFKThcbTAQGiF/bT1n2M+B1GTybRzMg6hyhOJeGPqIhLfJEpxn\nlJi4+ENAVT4MpqHEAGB8yFoPC0GqiOHQsdHxQV3P3c2OZqG+yJey74QtwA2tLcLn\nQ53c63+VLGsOjODl1yPn/2ejyq8qWu6ahfTxiIlSar2UbwtaQGBDFdb2CXgEufXT\nL7oaPxlmj+Q2oLOfOnInd2Oxop59HoJCQPsg8f921J43NCQGA8VHK6paxIRDLQID\nAQABozkwNzAJBgNVHRMEAjAAMAsGA1UdDwQEAwIEsDAdBgNVHQ4EFgQUvgTdT7fe\nx17ugO3IOsjEJwW7KP4wDQYJKoZIhvcNAQELBQADggEBAILiaB/unSVBfX5n7uL8\nveGGCOHuGYhCGqspb6mYiCx0dmV3RPRiEfGDLfzcXbHNx/3AjygcxH4Slr+pmaxr\n04Xli3WurocnjoANSWqCwpHH3OhSVxFgBNrCa3OMWcIr0xKH+I7PXA80SXe0pzfg\nePjpzTY71j+rcyRJqWiU5/zwdUaCCelBJscxh/0IaNcz67ocCEMRj0n4m5HFEmZL\n9zKkMZFoOjxRQjcL84QU7ZXnnFR5HG8nLw+NqWjo49W6MBQ9HGFda2tk3OpBhyWS\nsc3NyOkGUGdfiee5VRG31Sh3LLON3YGED+zZAS+ZF6598y4vhv8MBLa1Oy357byC\ntTg=\n-----END CERTIFICATE-----\n".freeze]
  s.date = "2022-04-20"
  s.description = "This module allows Ruby programs to interface with \"RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)\".".freeze
  s.email = ["ryosuke@deer-n-horse.jp".freeze, "gotoyuzo@notwork.org".freeze, "kanis@comcard.de".freeze]
  s.extensions = ["ext/extconf.rb".freeze]
  s.extra_rdoc_files = ["History.txt".freeze, "README.rdoc".freeze, "pkcs11_luna/Manifest.txt".freeze, "pkcs11_luna/README_LUNA.rdoc".freeze, "pkcs11_protect_server/Manifest.txt".freeze, "pkcs11_protect_server/README_PROTECT_SERVER.rdoc".freeze, "ext/pk11.c".freeze]
  s.files = ["History.txt".freeze, "README.rdoc".freeze, "ext/extconf.rb".freeze, "ext/pk11.c".freeze, "pkcs11_luna/Manifest.txt".freeze, "pkcs11_luna/README_LUNA.rdoc".freeze, "pkcs11_protect_server/Manifest.txt".freeze, "pkcs11_protect_server/README_PROTECT_SERVER.rdoc".freeze]
  s.homepage = "http://github.com/larskanis/pkcs11".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--main".freeze, "README.rdoc".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.2.0".freeze)
  s.rubygems_version = "3.3.7".freeze
  s.summary = "PKCS#11 binding for Ruby".freeze

  s.installed_by_version = "3.6.9".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<yard>.freeze, ["~> 0.6".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rake-compiler-dock>.freeze, ["~> 1.2".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.7".freeze])
  s.add_development_dependency(%q<hoe-bundler>.freeze, ["~> 1.0".freeze])
  s.add_development_dependency(%q<rdoc>.freeze, [">= 4.0".freeze, "< 7".freeze])
  s.add_development_dependency(%q<hoe>.freeze, ["~> 3.23".freeze])
end
