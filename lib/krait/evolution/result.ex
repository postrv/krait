defmodule Krait.Evolution.ValidatedProposal do
  @moduledoc "Struct for a validated evolution proposal"

  defstruct [
    :code,
    :test_code,
    :ast_hash,
    :complexity,
    :security_findings,
    :taint_flows,
    :spec
  ]
end
