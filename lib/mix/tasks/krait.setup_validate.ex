defmodule Mix.Tasks.Krait.SetupValidate do
  @moduledoc """
  Validate release-critical KRAIT setup.

  ## Usage

      mix krait.setup_validate
      mix krait.setup_validate --json
      mix krait.setup_validate --checks narsil,sandbox_image,github_auth
      mix krait.setup_validate --log-level info
  """

  use Mix.Task

  @shortdoc "Validate release-critical KRAIT setup"

  @check_names %{
    "database" => :database,
    "nif" => :nif,
    "narsil" => :narsil,
    "sandbox_image" => :sandbox_image,
    "github_auth" => :github_auth,
    "attestation_key" => :attestation_key,
    "llm" => :llm,
    "filesystem_sandbox" => :filesystem_sandbox,
    "admin_auth" => :admin_auth,
    "kill_switch" => :kill_switch
  }

  @impl true
  def run(args) do
    {opts, _positional, _invalid} =
      OptionParser.parse(args, strict: [json: :boolean, checks: :string, log_level: :string])

    validation_opts = validation_opts(opts)

    with_log_level(opts, fn ->
      Mix.Task.run("app.start")

      result =
        validation_opts
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
    end)
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
    |> Enum.map(fn check ->
      Map.get(@check_names, check) || Mix.raise("unknown check in --checks #{inspect(check)}")
    end)
  end

  defp with_log_level(opts, fun) do
    case Keyword.get(opts, :log_level) do
      nil ->
        fun.()

      level ->
        original = Logger.level()
        Logger.configure(level: parse_log_level(level))

        try do
          fun.()
        after
          Logger.configure(level: original)
        end
    end
  end

  defp parse_log_level(level) do
    case level do
      "debug" -> :debug
      "info" -> :info
      "warning" -> :warning
      "error" -> :error
      _ -> Mix.raise("unknown --log-level #{inspect(level)}")
    end
  end

  defp print_human(result) do
    Mix.shell().info("KRAIT setup validation: #{String.upcase(Atom.to_string(result.status))}")

    for check <- result.checks do
      Mix.shell().info("[#{check.status}] #{check.name}: #{check.message}")
    end
  end
end
