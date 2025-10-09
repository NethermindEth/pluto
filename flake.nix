{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/d7f52a7a640bc54c7bb414cca603835bf8dd4b10";
    utils.url = "github:numtide/flake-utils";
  };
  outputs = { nixpkgs, utils, ... }: utils.lib.eachDefaultSystem (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      devShells.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          rustc
          cargo
          rust-analyzer
          rustfmt
          clippy

          cargo-sort
          cargo-deny

          typos
        ];
        RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

        shellHook = ''
          chmod +x .githooks/* && ln -sf $(pwd)/.githooks/* .git/hooks/
        '';
      };

    }
  );
}
