# frozen_string_literal: true

require_relative 'test_helper'

class TestBegin < Minitest::Test
  def setup
    @now = Time.utc(2026, 1, 1)
    @material = LinkkeysLocalRp.generate_local_rp_identity(
      LinkkeysLocalRp::Identity::GenerateLocalRpIdentityConfig.new(app_name: 'Test App', now: @now)
    )
  end

  def begin_login(identity)
    LinkkeysLocalRp.begin_local_login(LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
      key_material: @material, callback_url: 'http://localhost/callback', user_domain: identity, now: @now
    ))
  end

  def test_identity_input_controls_destination_and_username_hint
    redirect, pending = begin_login('Alice+work@ID.Example.TEST')
    assert redirect.redirect_url.end_with?('&username=Alice%2Bwork')
    assert_equal 'id.example.test', pending.user_domain
    redirect, = begin_login('example.test')
    refute_includes redirect.redirect_url, 'username='
  end

  def test_malformed_identity_input_is_rejected
    %w[alice alice@@example.test https://example.test].each do |identity|
      assert_raises(LinkkeysLocalRp::Begin::Error) { begin_login(identity) }
    end
  end
end
