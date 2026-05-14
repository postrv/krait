defmodule Mix.Tasks.Krait.SetupValidate do
  @moduledoc """
  Validate release-critical KRAIT setup.

  ## Usage

      mix krait.setup_validate
      mix krait.setup_validate --json
      mix krait.setup_validate --checks narsil,sandbox_image,github_auth
  """

  use Mix.Task

  @shortdoc "Validate release-critical KRAIT setup"

  @impl true
  def run(args) do
    Mix.Task.run("app.start")

    {opts, _positional, _invalid} =
      OptionParser.parse(args, strict: [json: :boolean, checks: :string])

    result =
      opts
      |> validation_opts()
      |> Krait.SetupValidation.run()

    if Keyword.get(opts, :json, false) do
      result
      |> Krait.SetupValidation.to_json_map()
      |> Jason.encode!(pretty: true)
      |> Mix.shell().info()
    else
      print_human(result)
    end

    if result.status == :error do
      Mix.raise("setup validation failed")
    else
      :ok
    end
  end

  defp validation_opts(opts) do
    case Keyword.get(opts, :checks) do
      nil ->
        []

      checks ->
        [checks: parse_checks(checks)]
    end
  end

  defp parse_checks(checks) do
    checks
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.to_existing_atom/1)
  rescue
    ArgumentError ->
      Mix.raise("unknown check in --checks #{inspect(checks)}")
  end

  defp print_human(result) do
    Mix.shell().info("KRAIT setup validation: #{String.upcase(Atom.to_string(result.status))}")

    for check <- result.checks do
      Mix.shell().info("[#{check.status}] #{check.name}: #{check.message}")
    end
  end
end
