defmodule Mix.Tasks.Krait.SetupValidateTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

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
        assert :ok = Mix.Tasks.Krait.SetupValidate.run(["--json", "--checks", "github_auth"])
      end)

    assert output == ""
    assert_receive {:mix_shell, :info, [json]}

    decoded = Jason.decode!(json)
    assert decoded["status"] in ["ok", "warning", "error"]
    assert [%{"name" => "github_auth"}] = decoded["checks"]
  end
end
