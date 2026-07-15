defmodule LinkkeysLocalRp.ConformanceTicketsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Test.Vectors

  @tickets Vectors.load("tickets.json")

  test "ticket hashes match fingerprint routine" do
    cases = @tickets["cases"]
    assert length(cases) > 0

    for case_ <- cases do
      ticket = Vectors.hex(case_["ticket_hex"])
      assert byte_size(ticket) == 32
      assert Crypto.sha256_hex(ticket) == case_["sha256_hex"]
    end
  end
end
