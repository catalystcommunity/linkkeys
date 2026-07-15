# frozen_string_literal: true

require_relative 'lib/linkkeys_local_rp/version'

Gem::Specification.new do |spec|
  spec.name = 'linkkeys_local_rp'
  spec.version = LinkkeysLocalRp::VERSION
  spec.summary = 'LinkKeys DNS-less local RP identity SDK (Ruby)'
  spec.description = <<~DESC
    SDK for LinkKeys' DNS-less local RP identity mode: lets a locally
    installed app (LAN jukebox, desktop tool, self-hosted service with no
    public DNS) use LinkKeys for login without running its own DNS-pinned
    relying party. Zero gem dependencies -- built entirely on the bundled
    `openssl` gem (Ed25519/X25519/AES-256-GCM/ChaCha20-Poly1305/HKDF/SHA-256)
    and stdlib `resolv` (DNS TXT lookups for `_linkkeys`/`_linkkeys_apis`
    records).
  DESC
  spec.authors = ['LinkKeys']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.1'

  spec.files = Dir['lib/**/*.rb'] + ['README.md']
  spec.require_paths = ['lib']

  spec.metadata['rubygems_mfa_required'] = 'true'
end
