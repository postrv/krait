defmodule Krait.Test.EvolutionRunnerStub do
  @moduledoc false

  @spec evolve(map()) :: {:ok, map()}
  def evolve(params) do
    case Application.get_env(:krait, :evolution_runner_test_pid) do
      pid when is_pid(pid) -> send(pid, {:evolution_runner_called, self(), params})
      _ -> :ok
    end

    {:ok,
     %{
       pr_url: "https://github.com/org/krait/pull/test",
       attempts: 1,
       draft: false
     }}
  end
end
