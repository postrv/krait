defmodule Krait.Release.ImmutableGuardWorkflowTest do
  use ExUnit.Case, async: true

  @root File.cwd!()
  @workflow Path.join(@root, ".github/workflows/ci.yml")
  @manifest Path.join(@root, ".krait-immutable")

  test "pull request guard reruns when the constitutional label changes" do
    workflow = File.read!(@workflow)

    assert workflow =~
             "types: [opened, synchronize, reopened, labeled, unlabeled, ready_for_review]"
  end

  test "immutable guard reads the manifest from the trusted base commit" do
    workflow = File.read!(@workflow)

    assert workflow =~ ~s(git show "${BASE_SHA}:.krait-immutable" > "${BASE_MANIFEST}")
    refute workflow =~ "done < .krait-immutable"
  end

  test "immutable guard uses exact file and directory-prefix matching" do
    workflow = File.read!(@workflow)

    assert workflow =~ "matches_immutable_path()"
    assert workflow =~ ~s([[ "$immutable_path" == */ ]])
    assert workflow =~ ~s([[ "$changed_path" == "$immutable_path"* ]])
    assert workflow =~ ~s([[ "$changed_path" == "$immutable_path" ]])
    refute workflow =~ "grep -qF \"$path\""
  end

  test "github control-plane files are immutable" do
    manifest = File.read!(@manifest)

    assert manifest =~ "\n.github/\n"
    refute manifest =~ ".github/workflows/"
  end
end
