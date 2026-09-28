# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# passmcp as a Nix flake: a development shell, and the package itself.
#
#   nix develop          # every tool the CI gates need, pinned
#   nix build            # the passmcp package, with manpages + completions
#   nix run . -- --help  # run it without installing
#
# flake.lock is not committed yet: nix was not available on the machine
# that wrote this file, and a lock file written by hand is worse than none.
# Run `nix flake lock` once and commit the result.
{
  description = "passmcp: onboard, test and diagnose remote MCP servers end to end";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Read the version from CHANGELOG.md's newest release heading, so the
        # flake cannot drift from the changelog. Extracted by splitting
        # rather than by regex, which Nix's engine handles poorly for
        # bracketed headings.
        version =
          let
            lines = pkgs.lib.splitString "\n" (builtins.readFile ./CHANGELOG.md);
            isRelease = l:
              pkgs.lib.hasPrefix "## [" l && !(pkgs.lib.hasPrefix "## [Unreleased]" l);
            releases = builtins.filter isRelease lines;
            extract = l:
              builtins.head (pkgs.lib.splitString "]" (builtins.elemAt (pkgs.lib.splitString "[" l) 1));
          in
          if releases == [ ] then "0.0.0" else extract (builtins.head releases);

        passmcp = pkgs.buildGoModule {
          pname = "passmcp";
          inherit version;
          src = ./.;

          # Never guessed: `nix build` reports the expected value when go.mod
          # changes. Set on the first build and update on every go.mod change.
          vendorHash = pkgs.lib.fakeHash;

          subPackages = [ "cmd/passmcp" ];

          # Matches what the Makefile and goreleaser do: no CGO, paths
          # trimmed, version injected.
          env.CGO_ENABLED = 0;
          ldflags = [
            "-s"
            "-w"
            "-X satellion.com/passmcp/cmd.Version=${version}"
          ];

          nativeBuildInputs = [ pkgs.installShellFiles ];

          # Manpages and completions are generated from the cobra command
          # tree, never committed, so they are generated here too.
          postInstall = ''
            ${pkgs.go}/bin/go run ./scripts/gen_docs.go "$TMPDIR/artifacts"
            installManPage "$TMPDIR"/artifacts/man/*.1
            installShellCompletion --bash --name passmcp \
              "$TMPDIR/artifacts/completions/passmcp.bash"
            installShellCompletion --zsh --name _passmcp \
              "$TMPDIR/artifacts/completions/passmcp.zsh"
            installShellCompletion --fish --name passmcp.fish \
              "$TMPDIR/artifacts/completions/passmcp.fish"
            install -Dm644 README.md    "$out/share/doc/passmcp/README.md"
            install -Dm644 CHANGELOG.md "$out/share/doc/passmcp/CHANGELOG.md"
            install -Dm644 LICENSE      "$out/share/doc/passmcp/LICENSE"
            install -Dm644 SECURITY.md  "$out/share/doc/passmcp/SECURITY.md"
          '';

          # The suite makes no network calls: every server it talks to is an
          # httptest server in the same process, so it runs in the sandbox.
          # subPackages narrows checkPhase too, so the whole module is tested
          # explicitly.
          checkPhase = ''
            runHook preCheck
            go test ./...
            runHook postCheck
          '';

          meta = with pkgs.lib; {
            description = "Onboard, test and diagnose remote MCP servers end to end";
            homepage = "https://github.com/sebastienrousseau/passmcp";
            license = licenses.gpl3Only;
            mainProgram = "passmcp";
            maintainers = [ ];
          };
        };
      in
      {
        packages = {
          default = passmcp;
          passmcp = passmcp;
        };

        apps.default = flake-utils.lib.mkApp { drv = passmcp; };

        # Every tool DEVELOPMENT.md lists, pinned by the flake lock rather
        # than resolved at install time.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            golangci-lint
            gotools

            git
            gnumake
            groff # renders the generated manpages in the Install Contract gate

            markdownlint-cli2
            codespell
            lychee
            pre-commit
            python3Packages.mkdocs
            python3Packages.mkdocs-material

            goreleaser
            syft
            cosign
            gh
            actionlint
          ];

          shellHook = ''
            echo "passmcp dev shell: go $(go version | awk '{print $3}')"
            echo
            echo "  make            format, vet, lint, tests, build"
            echo "  make test-race  race detector, shuffled order"
            echo "  make help       every target"
            echo
            echo "See DEVELOPMENT.md for the local equivalent of every CI gate."
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
