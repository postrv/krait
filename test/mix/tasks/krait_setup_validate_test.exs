defmodule Mix.Tasks.Krait.SetupValidateTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Krait.SetupValidate

  setup do
    Mix.shell(Mix.Shell.Process)

    on_exit(fn ->
      Mix.shell(Mix.Shell.IO)
    end)

    :ok
  end

  test "prints JSON validation output" do
    output =
      capture_io(fn ->
        assert :ok = SetupValidate.run(["--json", "--checks", "github_auth"])
      end)

    assert output == ""
    assert_receive {:mix_shell, :info, [json]}

    decoded = Jason.decode!(json)
    assert decoded["status"] in ["ok", "warning", "error"]
    assert [%{"name" => "github_auth"}] = decoded["checks"]
  end

  test "accepts comma-separated setup checks through an explicit allowlist" do
    output =
      capture_io(fn ->
        assert :ok =
                 SetupValidate.run([
                   "--json",
                   "--checks",
                   "github_auth,llm,admin_auth"
                 ])
      end)

    assert output == ""
    assert_receive {:mix_shell, :info, [json]}

    decoded = Jason.decode!(json)
    assert Enum.map(decoded["checks"], & &1["name"]) == ["github_auth", "llm", "admin_auth"]
  end

  test "rejects unknown setup checks before validation runs" do
    assert_raise Mix.Error, ~r/unknown check in --checks "unknown"/, fn ->
      SetupValidate.run(["--checks", "github_auth,unknown"])
    end
  end

  test "accepts explicit log level for quiet installer validation" do
    output =
      capture_io(fn ->
        assert :ok =
                 SetupValidate.run([
                   "--json",
                   "--log-level",
                   "info",
                   "--checks",
                   "github_auth"
                 ])
      end)

    assert output == ""
    assert_receive {:mix_shell, :info, [json]}
    assert [%{"name" => "github_auth"}] = Jason.decode!(json)["checks"]
  end
end
