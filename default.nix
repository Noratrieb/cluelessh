{ pkgs ? import <nixpkgs> { }, ... }: pkgs.rustPlatform.buildRustPackage {
  src = pkgs.lib.cleanSource ./.;
  pname = "fakessh";
  version = "0.1.0";
  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    mainProgram = "fakessh";
  };
}
