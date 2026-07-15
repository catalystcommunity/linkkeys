# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require_relative '../lib/linkkeys_local_rp'

module ConformanceHelper
  CONFORMANCE_DIR = File.expand_path('../../conformance', __dir__)

  module_function

  def load_vector(name)
    JSON.parse(File.read(File.join(CONFORMANCE_DIR, name)))
  end

  def hex(str)
    raise "odd-length hex string: #{str.inspect}" unless str.length.even?

    [str].pack('H*')
  end

  def keys_vector = @keys_vector ||= load_vector('keys.json')
  def envelopes_vector = @envelopes_vector ||= load_vector('envelopes.json')
  def callback_box_vector = @callback_box_vector ||= load_vector('callback_box.json')
  def url_params_vector = @url_params_vector ||= load_vector('url_params.json')
  def dns_vector = @dns_vector ||= load_vector('dns.json')
  def tickets_vector = @tickets_vector ||= load_vector('tickets.json')
  def expirations_vector = @expirations_vector ||= load_vector('expirations.json')
  def revocations_vector = @revocations_vector ||= load_vector('revocations.json')
  def claims_vector = @claims_vector ||= load_vector('claims.json')
end
