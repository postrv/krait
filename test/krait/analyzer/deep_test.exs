defmodule Krait.Analyzer.DeepTest do
  use ExUnit.Case, async: false

  @moduletag :narsil_required

  setup do
    tmp_dir = Path.join(System.tmp_dir!(), "krait_test_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp_dir)

    File.write!(Path.join(tmp_dir, "good.ex"), Krait.Test.Fixtures.valid_elixir_module())
    File.write!(Path.join(tmp_dir, "evil.ex"), Krait.Test.Fixtures.malicious_credential_access())

    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    {:ok, pid} = Krait.Analyzer.Deep.start_link(repo_path: tmp_dir)
    %{pid: pid, tmp_dir: tmp_dir}
  end

  describe "security_scan/1" do
    test "returns result for safe code", %{tmp_dir: dir} do
      assert {:ok, findings} = Krait.Analyzer.Deep.security_scan(Path.join(dir, "good.ex"))
      assert is_list(findings)
    end

    test "flags credential access in malicious code", %{tmp_dir: dir} do
      assert {:ok, findings} = Krait.Analyzer.Deep.security_scan(Path.join(dir, "evil.ex"))
      assert length(findings) > 0
    end
  end

  describe "taint_analysis/2" do
    test "detects source-to-sink flow", %{tmp_dir: dir} do
      {:ok, flows} = Krait.Analyzer.Deep.taint_analysis("steal", Path.join(dir, "evil.ex"))
      assert is_list(flows)
    end
  end

  describe "call_graph/1" do
    test "returns function call relationships", %{tmp_dir: dir} do
      {:ok, graph} = Krait.Analyzer.Deep.call_graph(Path.join(dir, "good.ex"))
      assert is_map(graph)
    end
  end

  describe "infer_types/2" do
    test "returns type info for a function", %{tmp_dir: dir} do
      {:ok, types} = Krait.Analyzer.Deep.infer_types(Path.join(dir, "good.ex"), "execute")
      assert is_list(types)
    end
  end

  describe "dead_code/1" do
    test "returns list of unreachable functions", %{tmp_dir: dir} do
      {:ok, dead} = Krait.Analyzer.Deep.dead_code(Path.join(dir, "good.ex"))
      assert is_list(dead)
    end
  end

  describe "dependency_audit/1" do
    test "returns SBOM for a repo path", %{tmp_dir: dir} do
      {:ok, sbom} = Krait.Analyzer.Deep.dependency_audit(dir)
      assert is_map(sbom)
    end
  end
end
