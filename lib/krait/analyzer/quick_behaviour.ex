defmodule Krait.Analyzer.QuickBehaviour do
  @moduledoc "Contract for quick (NIF-level) code analysis"

  @type validation_result ::
          {:ok, %{complexity: non_neg_integer(), hash: String.t()}}
          | {:syntax_error, [%{line: non_neg_integer(), message: String.t()}]}
          | {:policy_violation, %{rule: String.t(), location: map(), explanation: String.t()}}

  @callback quick_validate(code :: String.t(), language :: String.t()) :: validation_result()
end
